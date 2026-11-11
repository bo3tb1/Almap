/* iot-lwm2m-discover-5 - LwM2M CoAP discovery probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 21] = [0x40, 0x01, 0x12, 0x34, 0xbb, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x44, 0x63, 0x6f, 0x72, 0x65];
    if !valid(ctx) {
        return 1;
    }
    let buf = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "iot-lwm2m-discover-5: no UDP reply");
            return 0;
        }
    };
    let text = clean(&String::from_utf8_lossy(&buf));
    if contains_ci(&text, "core") {
        set_out(ctx, "iot-lwm2m-discover-5: detected");
    } else {
        set_out(ctx, "iot-lwm2m-discover-5: not detected");
    }
    0
}
