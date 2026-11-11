/* svc-memcached-5 - Memcached stats probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 7] = [0x73, 0x74, 0x61, 0x74, 0x73, 0x0d, 0x0a];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-memcached-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &REQ).is_err() {
        set_out(ctx, "svc-memcached-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "svc-memcached-5: no response");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    if contains_ci(&cleaned, "STAT") {
        set_out(ctx, "svc-memcached-5: detected");
    } else {
        set_out(ctx, "svc-memcached-5: not detected");
    }
    0
}
