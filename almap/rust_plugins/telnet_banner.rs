/* telnet_banner - read the raw Telnet banner; keep CR/LF/TAB, replace
 * other control bytes (and 0x7f/0xff) with '.'. */
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
    let resp = recv_all(&mut s, 3000);
    drop(s);
    if resp.is_empty() {
        return 0;
    }
    let mut filtered: Vec<u8> = Vec::with_capacity(resp.len());
    for &c in resp.iter() {
        if c == 0
            || (c < 32 && c != b'\r' && c != b'\n' && c != b'\t')
            || c == 127
            || c == 255
        {
            filtered.push(b'.');
        } else {
            filtered.push(c);
        }
    }
    set_out(ctx, &String::from_utf8_lossy(&filtered));
    0
}
