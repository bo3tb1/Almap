/* svc-http-proxy-5 - HTTP CONNECT proxy probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("svc-http-proxy-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[67, 79, 78, 78, 69, 67, 84, 32, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 58, 52, 52, 51, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 111, 115, 116, 58, 32, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 58, 52, 52, 51, 13, 10, 13, 10]).is_err() {
    set_out(ctx, "svc-http-proxy-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "svc-http-proxy-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "200") {
    set_out(ctx, "svc-http-proxy-5: detected");
} else {
    set_out(ctx, "svc-http-proxy-5: not detected");
}
0
}
