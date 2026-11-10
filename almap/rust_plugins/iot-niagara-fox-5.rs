/* iot-niagara-fox-5 - Niagara Fox hello probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("iot-niagara-fox-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[102, 111, 120, 32, 97, 32, 49, 32, 45, 49, 32, 102, 111, 120, 32, 104, 101, 108, 108, 111, 10, 123, 10, 102, 111, 120, 46, 118, 101, 114, 115, 105, 111, 110, 61, 115, 58, 49, 46, 48, 10, 104, 111, 115, 116, 78, 97, 109, 101, 61, 115, 58, 97, 108, 109, 97, 112, 10, 97, 112, 112, 46, 110, 97, 109, 101, 61, 115, 58, 97, 108, 109, 97, 112, 10, 97, 112, 112, 46, 118, 101, 114, 115, 105, 111, 110, 61, 115, 58, 49, 46, 48, 10, 118, 109, 46, 110, 97, 109, 101, 61, 115, 58, 106, 97, 118, 97, 10, 118, 109, 46, 118, 101, 114, 115, 105, 111, 110, 61, 115, 58, 49, 46, 56, 10, 111, 115, 46, 110, 97, 109, 101, 61, 115, 58, 108, 105, 110, 117, 120, 10, 111, 115, 46, 118, 101, 114, 115, 105, 111, 110, 61, 115, 58, 53, 46, 48, 10, 108, 97, 110, 103, 117, 97, 103, 101, 61, 115, 58, 101, 110, 10, 99, 111, 117, 110, 116, 114, 121, 61, 115, 58, 85, 83, 10, 125, 10]).is_err() {
    set_out(ctx, "iot-niagara-fox-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "iot-niagara-fox-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "fox") {
    set_out(ctx, "iot-niagara-fox-5: detected");
} else {
    set_out(ctx, "iot-niagara-fox-5: not detected");
}
0
}
