/* iot-knx-search-5 - KNXnet/IP search request probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 14] = [0x06, 0x10, 0x02, 0x01, 0x00, 0x0e, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "iot-knx-search-5: no UDP reply");
            return 0;
        }
    };
    if resp.len() >= 6 && resp[2] == 0x02 {
        set_out(ctx, &format!("iot-knx-search-5: expected reply seen ({} bytes)", resp.len()));
    } else {
        set_out(ctx, &format!("iot-knx-search-5: unexpected reply ({} bytes)", resp.len()));
    }
    0
}
