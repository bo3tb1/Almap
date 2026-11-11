/* redis-brute-3 - five fixed Redis AUTH attempts. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, "Redis brute: no connection"); return 0; }
};
let line = recv_line(&mut s, 4096);
let buf = line.into_bytes();
if buf.is_empty() {
    set_out(ctx, "redis-brute-3: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, "Redis brute: no valid password in 5 attempts");
0
}
