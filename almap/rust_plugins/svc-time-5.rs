/* svc-time-5 - Time service probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-time-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &REQ).is_err() {
        set_out(ctx, "svc-time-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "svc-time-5: no response");
        return 0;
    }
    let n = resp.len();
    if n >= 4 {
        set_out(ctx, &format!("svc-time-5: expected reply seen ({} bytes)", n));
    } else {
        set_out(ctx, &format!("svc-time-5: unexpected reply ({} bytes)", n));
    }
    0
}
