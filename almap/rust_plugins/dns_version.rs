/* dns-version - CHAOS TXT query for version.bind. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

const DNS_QUERY_ID: u16 = 0x414C;

fn dns_skip_name(msg: &[u8], pos: &mut usize) -> bool {
    let n = msg.len();
    let mut p = *pos;
    let mut guard = 0;
    while p < n && guard < 128 {
        guard += 1;
        let l = msg[p];
        if (l & 0xC0) == 0xC0 {
            if p + 1 >= n {
                return false;
            }
            *pos = p + 2;
            return true;
        }
        if l == 0 {
            *pos = p + 1;
            return true;
        }
        if p + 1 + l as usize > n {
            return false;
        }
        p += 1 + l as usize;
    }
    false
}

fn dns_parse_txt(msg: &[u8]) -> Option<String> {
    let n = msg.len();
    if n < 12 {
        return None;
    }
    let ancount = ((msg[6] as usize) << 8) | msg[7] as usize;
    if ancount == 0 {
        return None;
    }
    let mut p = 12usize;
    if !dns_skip_name(msg, &mut p) || p + 4 > n {
        return None;
    }
    p += 4;
    for _ in 0..ancount.min(16) {
        if !dns_skip_name(msg, &mut p) || p + 10 > n {
            return None;
        }
        let rtype = ((msg[p] as usize) << 8) | msg[p + 1] as usize;
        let rdlen = ((msg[p + 8] as usize) << 8) | msg[p + 9] as usize;
        p += 10;
        if p + rdlen > n {
            return None;
        }
        if rtype == 16 && rdlen > 0 {
            let end = p + rdlen;
            let mut out = String::new();
            while p < end {
                let slen = msg[p] as usize;
                p += 1;
                if p + slen > end {
                    break;
                }
                out.push_str(&String::from_utf8_lossy(&msg[p..p + slen]));
                p += slen;
                if p < end && !out.is_empty() {
                    out.push(' ');
                }
            }
            let out = clean(&out);
            if !out.is_empty() {
                return Some(out);
            }
            return None;
        }
        p += rdlen;
    }
    None
}

fn dns_build_query() -> Vec<u8> {
    let mut req = Vec::with_capacity(32);
    req.push((DNS_QUERY_ID >> 8) as u8);
    req.push((DNS_QUERY_ID & 255) as u8);
    req.push(0x01); /* recursion desired */
    req.push(0x00);
    req.push(0x00); /* QDCOUNT */
    req.push(0x01);
    req.push(0x00); /* ANCOUNT */
    req.push(0x00);
    req.push(0x00); /* NSCOUNT */
    req.push(0x00);
    req.push(0x00); /* ARCOUNT */
    req.push(0x00);
    req.push(7);
    req.extend_from_slice(b"version");
    req.push(4);
    req.extend_from_slice(b"bind");
    req.push(0);
    req.push(0x00); /* QTYPE TXT */
    req.push(0x10);
    req.push(0x00); /* QCLASS CH */
    req.push(0x03);
    req
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let req = dns_build_query();
    if let Some(resp) = udp_exchange(ctx, &req, 2048) {
        if resp.len() >= 12 {
            if let Some(text) = dns_parse_txt(&resp) {
                set_out(ctx, &format!("version.bind: {}", text));
                return 0;
            }
        }
    }
    /* DNS over TCP fallback: two-byte length prefix. */
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 0,
    };
    let mut frame = Vec::with_capacity(req.len() + 2);
    frame.push((req.len() >> 8) as u8);
    frame.push((req.len() & 255) as u8);
    frame.extend_from_slice(&req);
    if send_all(&mut stream, &frame).is_err() {
        return 0;
    }
    let hdr = match recv_exact(&mut stream, 2) {
        Some(h) => h,
        None => return 0,
    };
    let mlen = ((hdr[0] as usize) << 8) | hdr[1] as usize;
    if mlen < 12 || mlen > 2048 {
        return 0;
    }
    let resp = match recv_exact(&mut stream, mlen) {
        Some(r) => r,
        None => return 0,
    };
    drop(stream);
    if let Some(text) = dns_parse_txt(&resp) {
        set_out(ctx, &format!("version.bind: {}", text));
    }
    0
}
