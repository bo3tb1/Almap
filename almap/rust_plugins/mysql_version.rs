/*
 * mysql_version.rs - NSE mysql-info analog (version only).
 *
 * Reads the MySQL initial handshake packet and extracts the
 * NUL-terminated server version string.
 * Output: "mysql_version:<version>" (empty when not MySQL).
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }

    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    let hdr = match recv_exact(&mut s, 4) {
        Some(h) => h,
        None => return 0,
    };
    let plen = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    if plen < 2 || plen > 3072 {
        return 0;
    }
    let pkt = match recv_exact(&mut s, plen) {
        Some(p) => p,
        None => return 0,
    };
    drop(s);

    /* payload[0] is the protocol version, then the server version. */
    let max = plen - 1;
    let mut version: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < max && pkt[1 + i] != 0 && i < 255 {
        version.push(pkt[1 + i]);
        i += 1;
    }
    let text = clean(&String::from_utf8_lossy(&version));
    if !text.is_empty() {
        set_out(ctx, &format!("mysql_version:{}", text));
    }
    0
}
