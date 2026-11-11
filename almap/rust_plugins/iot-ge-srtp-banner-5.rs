/* iot-ge-srtp-banner-5 - GE SRTP banner probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("iot-ge-srtp-banner-5: TCP {} not reachable", port)); return 0; }
};
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "iot-ge-srtp-banner-5: no banner");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("iot-ge-srtp-banner-5: {}", &resp));
0
}
