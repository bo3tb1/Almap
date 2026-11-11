/* iot-ipmi-rmcp-5 - IPMI RMCP presence probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 20] = [0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "iot-ipmi-rmcp-5: no UDP reply");
            return 0;
        }
    };
    if resp.len() >= 4 && resp[0] == 0x06 && resp[1] == 0x00 && resp[2] == 0xff && resp[3] == 0x07 {
        set_out(ctx, &format!("iot-ipmi-rmcp-5: expected reply seen ({} bytes)", resp.len()));
    } else {
        set_out(ctx, &format!("iot-ipmi-rmcp-5: unexpected reply ({} bytes)", resp.len()));
    }
    0
}
