/* iot-bacnet-readprop-5 - BACnet/IP ReadProperty probe
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 16] = [
        0x81, 0x0a, 0x00, 0x10, 0x01, 0x04, 0x00, 0x05,
        0x01, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x19, 0x55,
    ];

    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &req, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "iot-bacnet-readprop-5: no UDP reply");
            return 0;
        }
    };
    if resp.len() >= 4 && resp[0] == 0x81 {
        set_out(
            ctx,
            &format!(
                "iot-bacnet-readprop-5: expected reply seen ({} bytes)",
                resp.len()
            ),
        );
    } else {
        set_out(
            ctx,
            &format!(
                "iot-bacnet-readprop-5: unexpected reply ({} bytes)",
                resp.len()
            ),
        );
    }
    0
}
