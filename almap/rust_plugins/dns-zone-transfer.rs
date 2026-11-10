/*
 * dns-zone-transfer (Rust) - attempt AXFR for likely zones. Faithful
 * port of dns-zone-transfer.c with the arsenal_dns.h wire helpers it
 * needs (query build, TCP framing, rcode, compression-aware answer
 * dumping). Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

const AR_DNS_A: u32 = 1;
const AR_DNS_NS: u32 = 2;
const AR_DNS_CNAME: u32 = 5;
const AR_DNS_SOA: u32 = 6;
const AR_DNS_PTR: u32 = 12;
const AR_DNS_MX: u32 = 15;
const AR_DNS_TXT: u32 = 16;
const AR_DNS_AAAA: u32 = 28;
const AR_DNS_AXFR: u32 = 252;

/// Encode a domain name into length-prefixed labels (port of
/// ar_dns_encode_name).
fn dns_encode_name(name: &str) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(out)
}

/// Build a DNS query message (port of ar_dns_make_query).
fn dns_make_query(name: &str, qtype: u32, flags: u32) -> Option<Vec<u8>> {
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        & 0xFFFF) as u32;
    let mut buf = vec![0u8; 12];
    buf[0] = (id >> 8) as u8;
    buf[1] = (id & 0xFF) as u8;
    buf[2] = (flags >> 8) as u8;
    buf[3] = (flags & 0xFF) as u8;
    buf[5] = 1; // QDCOUNT
    let qname = dns_encode_name(name)?;
    buf.extend_from_slice(&qname);
    buf.push((qtype >> 8) as u8);
    buf.push((qtype & 0xFF) as u8);
    buf.push(0);
    buf.push(1); // IN
    Some(buf)
}

/// Send a DNS message over TCP (2-byte length prefix).
fn dns_tcp_send(s: &mut TcpStream, pkt: &[u8]) -> bool {
    if pkt.len() > 65535 {
        return false;
    }
    let hdr = [(pkt.len() >> 8) as u8, (pkt.len() & 0xFF) as u8];
    as_send_all(s, &hdr) && as_send_all(s, pkt)
}

/// Receive one TCP DNS message (port of ar_dns_tcp_recv).
fn dns_tcp_recv(s: &mut TcpStream, timeout_ms: i32) -> Option<Vec<u8>> {
    set_rtimeout(s, timeout_ms);
    let mut hdr = [0u8; 2];
    if !as_recv_exact(s, &mut hdr) {
        return None;
    }
    let len = ((hdr[0] as usize) << 8) | hdr[1] as usize;
    let mut out = vec![0u8; len];
    if len > 0 && !as_recv_exact(s, &mut out) {
        return None;
    }
    Some(out)
}

fn dns_rcode(resp: &[u8]) -> i32 {
    if resp.len() < 4 {
        return -1;
    }
    (resp[3] & 15) as i32
}

fn dns_qdcount(resp: &[u8]) -> usize {
    if resp.len() < 6 {
        return 0;
    }
    ((resp[4] as usize) << 8) | resp[5] as usize
}

fn dns_ancount(resp: &[u8]) -> usize {
    if resp.len() < 8 {
        return 0;
    }
    ((resp[6] as usize) << 8) | resp[7] as usize
}

/// Bytes consumed by a name starting at `start` (port of ar_dns_name_len).
fn dns_name_len(data: &[u8], start: usize, end: usize) -> Option<usize> {
    let mut p = start;
    while p < end {
        if data[p] & 0xC0 == 0xC0 {
            return if p + 2 <= end { Some(p + 2 - start) } else { None };
        }
        if data[p] == 0 {
            return Some(p + 1 - start);
        }
        let l = data[p] as usize;
        if p + 1 + l > end {
            return None;
        }
        p += 1 + l;
    }
    None
}

/// Decode a (possibly compressed) name at offset `off` (port of
/// ar_dns_name_at).
fn dns_name_at(base: &[u8], off: usize) -> Option<String> {
    let len = base.len();
    if off >= len {
        return None;
    }
    let mut out = String::new();
    let mut off = off;
    let mut guard = 0;
    while off < len && guard < 64 {
        guard += 1;
        let p = base[off];
        if p & 0xC0 == 0xC0 {
            if off + 1 >= len {
                return None;
            }
            off = ((p as usize & 0x3F) << 8) | base[off + 1] as usize;
            continue;
        }
        if p == 0 {
            break;
        }
        let l = p as usize;
        if off + 1 + l > len {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&base[off + 1..off + 1 + l]));
        off += 1 + l;
    }
    if out.is_empty() {
        out.push('.');
    }
    Some(out)
}

/// Dump up to `max` answers as "name TYPE value" lines (port of
/// ar_dns_dump_answers). Returns the number printed.
fn dns_dump_answers(ctx: &AlScriptContext, resp: &[u8], max: usize) -> usize {
    let len = resp.len();
    if len < 12 {
        return 0;
    }
    let qd = dns_qdcount(resp);
    let an = dns_ancount(resp);
    let mut off = 12usize;
    let mut printed = 0usize;
    for _ in 0..qd {
        match dns_name_len(resp, off, len) {
            Some(nl) if off + nl + 4 <= len => off += nl + 4,
            _ => return printed,
        }
    }
    for _ in 0..an {
        if printed >= max {
            break;
        }
        let nl = match dns_name_len(resp, off, len) {
            Some(n) if off + n + 10 <= len => n,
            _ => break,
        };
        let name = dns_name_at(resp, off).unwrap_or_else(|| "?".to_string());
        off += nl;
        let rtype = ((resp[off] as u32) << 8) | resp[off + 1] as u32;
        let rdlen = (((resp[off + 8] as usize) << 8) | resp[off + 9] as usize) as usize;
        off += 10;
        if off + rdlen > len {
            break;
        }
        let val: String = if rtype == AR_DNS_A && rdlen == 4 {
            format!("{}.{}.{}.{}", resp[off], resp[off + 1], resp[off + 2], resp[off + 3])
        } else if rtype == AR_DNS_AAAA && rdlen == 16 {
            let g = &resp[off..off + 16];
            format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7], g[8], g[9], g[10], g[11], g[12],
                g[13], g[14], g[15]
            )
        } else if rtype == AR_DNS_CNAME || rtype == AR_DNS_NS || rtype == AR_DNS_PTR {
            dns_name_at(resp, off).unwrap_or_default()
        } else if rtype == AR_DNS_TXT && rdlen > 0 {
            let mut tl = resp[off] as usize;
            if tl > rdlen - 1 {
                tl = rdlen - 1;
            }
            ar_clean(&resp[off + 1..off + 1 + tl])
        } else if rtype == AR_DNS_SOA {
            "SOA".to_string()
        } else if rtype == AR_DNS_MX && rdlen >= 3 {
            let pref = ((resp[off] as u32) << 8) | resp[off + 1] as u32;
            let mx = dns_name_at(resp, off + 2).unwrap_or_default();
            format!("{} {}", pref, mx)
        } else {
            format!("{} bytes", rdlen)
        };
        let tname = match rtype {
            AR_DNS_A => "A",
            AR_DNS_AAAA => "AAAA",
            AR_DNS_CNAME => "CNAME",
            AR_DNS_NS => "NS",
            AR_DNS_PTR => "PTR",
            AR_DNS_MX => "MX",
            AR_DNS_TXT => "TXT",
            AR_DNS_SOA => "SOA",
            _ => "TYPE",
        };
        if printed > 0 {
            ar_append(ctx, "\n");
        }
        ar_append(ctx, &format!("{} {} {}", name, tname, val));
        printed += 1;
        off += rdlen;
    }
    printed
}

fn axfr_try(ctx: &AlScriptContext, zone: &str) -> i32 {
    let req = match dns_make_query(zone, AR_DNS_AXFR, 0x0000) {
        Some(r) => r,
        None => return -1,
    };
    let mut s = match as_connect(ctx) {
        Some(s) => s,
        None => return -1,
    };
    if !dns_tcp_send(&mut s, &req) {
        return -1;
    }
    let mut total = 0i32;
    let mut first = true;
    for _ in 0..8 {
        let resp = match dns_tcp_recv(&mut s, 500) {
            Some(r) if !r.is_empty() => r,
            _ => break,
        };
        if dns_rcode(&resp) != 0 {
            break;
        }
        if first {
            ar_append(ctx, &format!("DNS zone transfer: {}\n", zone));
            first = false;
        }
        total += dns_dump_answers(ctx, &resp, 12) as i32;
    }
    total
}

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let ip = as_ip_text(ctx.target_ip);
    let reverse = format!("{}.in-addr.arpa", ip);
    if axfr_try(ctx, &reverse) > 0 {
        return 0;
    }
    for z in ["example.com", "test", "local"].iter() {
        if axfr_try(ctx, z) > 0 {
            return 0;
        }
    }
    ar_out(ctx, "DNS zone transfer: refused or no records");
    0
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if ctx.is_null() {
        return 1;
    }
    let ctx: &AlScriptContext = unsafe { &*ctx };
    run(ctx)
}
