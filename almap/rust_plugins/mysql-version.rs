/* mysql-version - read the MySQL initial handshake server version. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    let hdr = match recv_exact(&mut stream, 4) {
        Some(h) => h,
        None => return 0,
    };
    let plen = (hdr[0] as usize) | ((hdr[1] as usize) << 8) | ((hdr[2] as usize) << 16);
    if plen < 2 || plen > 3072 {
        return 0;
    }
    let pkt = match recv_exact(&mut stream, plen) {
        Some(p) => p,
        None => return 0,
    };
    drop(stream);
    let max = plen - 1;
    let mut raw: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < max && pkt[1 + i] != 0 && i < 255 {
        raw.push(pkt[1 + i]);
        i += 1;
    }
    let version = clean(&String::from_utf8_lossy(&raw));
    if !version.is_empty() {
        set_out(ctx, &format!("mysql_version:{}", version));
    }
    0
}
