/* svc-rlogin-5 - rlogin service probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 17] = [0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x76, 0x74, 0x31, 0x30, 0x30, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-rlogin-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &REQ).is_err() {
        set_out(ctx, "svc-rlogin-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "svc-rlogin-5: no response");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    let show: String = cleaned.chars().take(220).collect();
    set_out(ctx, &format!("svc-rlogin-5: {}", show));
    0
}
