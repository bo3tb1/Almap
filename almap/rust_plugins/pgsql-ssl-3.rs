/* pgsql-ssl-3 - PostgreSQL SSL negotiation probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, "PostgreSQL SSL: no connection"); return 0; }
};
if send_all(&mut s, &[0, 0, 0, 8, 4, 210, 22, 47]).is_err() {
    set_out(ctx, "pgsql-ssl-3: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "PostgreSQL SSL: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("PostgreSQL SSL: unexpected response 0x{:02x}", rb[0]));
0
}
