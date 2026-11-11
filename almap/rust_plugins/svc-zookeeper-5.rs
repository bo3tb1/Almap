/* svc-zookeeper-5 - ZooKeeper ruok probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 4] = [0x72, 0x75, 0x6f, 0x6b];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-zookeeper-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &REQ).is_err() {
        set_out(ctx, "svc-zookeeper-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "svc-zookeeper-5: no response");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    if contains_ci(&cleaned, "imok") {
        set_out(ctx, "svc-zookeeper-5: detected");
    } else {
        set_out(ctx, "svc-zookeeper-5: not detected");
    }
    0
}
