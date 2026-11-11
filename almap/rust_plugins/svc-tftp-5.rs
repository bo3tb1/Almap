/* svc-tftp-5 - TFTP read-request probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 14] = [0x00, 0x01, 0x61, 0x6c, 0x6d, 0x61, 0x70, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &REQ, 2048) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "svc-tftp-5: no UDP reply");
            return 0;
        }
    };
    let n = resp.len();
    if n >= 4 && (resp[1] == 0x03 || resp[1] == 0x05) {
        set_out(ctx, &format!("svc-tftp-5: expected reply seen ({} bytes)", n));
    } else {
        set_out(ctx, &format!("svc-tftp-5: unexpected reply ({} bytes)", n));
    }
    0
}
