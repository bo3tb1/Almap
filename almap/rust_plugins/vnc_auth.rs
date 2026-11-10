/* vnc_auth - * plugins/vnc_auth.c - NSE vnc-info analog (auth types only). * * Build: * gcc -shared -fPIC -o plugins/vnc_auth.so plugins/vnc_auth.c * Run */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("vnc_auth: TCP {} not reachable", port)); return 0; }
};
let buf = recv_exact(&mut s, 4096).unwrap_or_default();
if buf.is_empty() {
    set_out(ctx, "vnc_auth: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("vnc_auth: {}", &resp.chars().take(220).collect::<String>()));
0
}
