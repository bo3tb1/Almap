/* iot-stomp-connect-5 - STOMP CONNECT probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("iot-stomp-connect-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[67, 79, 78, 78, 69, 67, 84, 10, 97, 99, 99, 101, 112, 116, 45, 118, 101, 114, 115, 105, 111, 110, 58, 49, 46, 50, 10, 104, 111, 115, 116, 58, 97, 108, 109, 97, 112, 10, 10, 0]).is_err() {
    set_out(ctx, "iot-stomp-connect-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "iot-stomp-connect-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "CONNECTED") {
    set_out(ctx, "iot-stomp-connect-5: detected");
} else {
    set_out(ctx, "iot-stomp-connect-5: not detected");
}
0
}
