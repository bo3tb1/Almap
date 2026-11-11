/* iot-profinet-dcp-identify-5 - PROFINET DCP identify-all probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 16] = [0xfe, 0xfe, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "iot-profinet-dcp-identify-5: no UDP reply");
            return 0;
        }
    };
    if resp.len() >= 2 && resp[0] == 0xfe {
        set_out(ctx, &format!("iot-profinet-dcp-identify-5: expected reply seen ({} bytes)", resp.len()));
    } else {
        set_out(ctx, &format!("iot-profinet-dcp-identify-5: unexpected reply ({} bytes)", resp.len()));
    }
    0
}
