/* svc-x11-5 - X11 setup-request probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("svc-x11-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[108, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err() {
    set_out(ctx, "svc-x11-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "svc-x11-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 0 && buf[0] == 1 {
    set_out(ctx, &format!("svc-x11-5: expected reply seen ({} bytes)", resp.len()));
} else {
    set_out(ctx, &format!("svc-x11-5: unexpected reply ({} bytes)", resp.len()));
}
0
}
