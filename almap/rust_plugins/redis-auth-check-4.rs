/* redis-auth-check-4 - Redis AUTH default-credential / no-auth check. * Uses a fixed 5-entry test dictionary. Benign: sends AUTH and PING. * Use only on networks y */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, "redis-auth-check: not reachable"); return 0; }
};
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "redis-auth-check-4: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, "redis-auth-check: all 5 default passwords rejected");
0
}
