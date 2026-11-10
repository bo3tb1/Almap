/* svc-memcached-5 - Memcached stats probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("svc-memcached-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[115, 116, 97, 116, 115, 13, 10]).is_err() {
    set_out(ctx, "svc-memcached-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "svc-memcached-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "STAT") {
    set_out(ctx, "svc-memcached-5: detected");
} else {
    set_out(ctx, "svc-memcached-5: not detected");
}
0
}
