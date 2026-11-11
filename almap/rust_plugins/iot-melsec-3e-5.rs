/* iot-melsec-3e-5 - Mitsubishi MELSEC 3E frame probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("iot-melsec-3e-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[80, 0, 0, 255, 255, 3, 0, 12, 0, 16, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0]).is_err() {
    set_out(ctx, "iot-melsec-3e-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "iot-melsec-3e-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 0 && buf[0] == 208 {
    set_out(ctx, &format!("iot-melsec-3e-5: expected reply seen ({} bytes)", resp.len()));
} else {
    set_out(ctx, &format!("iot-melsec-3e-5: unexpected reply ({} bytes)", resp.len()));
}
0
}
