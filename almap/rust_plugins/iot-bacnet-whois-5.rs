/* iot-bacnet-whois-5 - BACnet/IP Who-Is discovery probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 12] = [0x81, 0x0a, 0x00, 0x0c, 0x01, 0x20, 0xff, 0xff, 0x00, 0xff, 0x10, 0x08];
    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "iot-bacnet-whois-5: no UDP reply");
            return 0;
        }
    };
    if resp.len() >= 4 && resp[0] == 0x81 {
        set_out(ctx, &format!("iot-bacnet-whois-5: expected reply seen ({} bytes)", resp.len()));
    } else {
        set_out(ctx, &format!("iot-bacnet-whois-5: unexpected reply ({} bytes)", resp.len()));
    }
    0
}
