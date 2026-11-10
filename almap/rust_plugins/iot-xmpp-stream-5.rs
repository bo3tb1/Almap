/* iot-xmpp-stream-5 - XMPP stream-header probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("iot-xmpp-stream-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[60, 63, 120, 109, 108, 32, 118, 101, 114, 115, 105, 111, 110, 61, 39, 49, 46, 48, 39, 63, 62, 60, 115, 116, 114, 101, 97, 109, 58, 115, 116, 114, 101, 97, 109, 32, 116, 111, 61, 39, 97, 108, 109, 97, 112, 39, 32, 120, 109, 108, 110, 115, 61, 39, 106, 97, 98, 98, 101, 114, 58, 99, 108, 105, 101, 110, 116, 39, 32, 120, 109, 108, 110, 115, 58, 115, 116, 114, 101, 97, 109, 61, 39, 104, 116, 116, 112, 58, 47, 47, 101, 116, 104, 101, 114, 120, 46, 106, 97, 98, 98, 101, 114, 46, 111, 114, 103, 47, 115, 116, 114, 101, 97, 109, 115, 39, 32, 118, 101, 114, 115, 105, 111, 110, 61, 39, 49, 46, 48, 39, 62]).is_err() {
    set_out(ctx, "iot-xmpp-stream-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "iot-xmpp-stream-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "stream:stream") {
    set_out(ctx, "iot-xmpp-stream-5: detected");
} else {
    set_out(ctx, "iot-xmpp-stream-5: not detected");
}
0
}
