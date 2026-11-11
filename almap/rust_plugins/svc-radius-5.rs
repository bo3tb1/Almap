/* svc-radius-5 - RADIUS access-request probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 20] = [0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &REQ, 2048) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "svc-radius-5: no UDP reply");
            return 0;
        }
    };
    let n = resp.len();
    if !resp.is_empty() && (resp[0] == 2 || resp[0] == 3 || resp[0] == 11) {
        set_out(ctx, &format!("svc-radius-5: expected reply seen ({} bytes)", n));
    } else {
        set_out(ctx, &format!("svc-radius-5: unexpected reply ({} bytes)", n));
    }
    0
}
