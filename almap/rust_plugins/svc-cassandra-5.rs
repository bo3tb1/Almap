/* svc-cassandra-5 - Cassandra native-protocol OPTIONS probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 9] = [0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-cassandra-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &REQ).is_err() {
        set_out(ctx, "svc-cassandra-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "svc-cassandra-5: no response");
        return 0;
    }
    let n = resp.len();
    if n >= 5 && resp[4] == 0x06 {
        set_out(ctx, &format!("svc-cassandra-5: expected reply seen ({} bytes)", n));
    } else {
        set_out(ctx, &format!("svc-cassandra-5: unexpected reply ({} bytes)", n));
    }
    0
}
