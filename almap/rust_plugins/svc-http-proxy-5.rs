/* svc-http-proxy-5 - HTTP CONNECT proxy probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 59] = [0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x20, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x34, 0x34, 0x33, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x34, 0x34, 0x33, 0x0d, 0x0a, 0x0d, 0x0a];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-http-proxy-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &REQ).is_err() {
        set_out(ctx, "svc-http-proxy-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "svc-http-proxy-5: no response");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    if contains_ci(&cleaned, "200") {
        set_out(ctx, "svc-http-proxy-5: detected");
    } else {
        set_out(ctx, "svc-http-proxy-5: not detected");
    }
    0
}
