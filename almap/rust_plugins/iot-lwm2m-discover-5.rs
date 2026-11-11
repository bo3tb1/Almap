/* iot-lwm2m-discover-5 - LwM2M CoAP discovery probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = &[64, 1, 18, 52, 187, 46, 119, 101, 108, 108, 45, 107, 110, 111, 119, 110, 68, 99, 111, 114, 101];
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "iot-lwm2m-discover-5: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, "iot-lwm2m-discover-5: not detected");
0
}
