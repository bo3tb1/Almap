/* mqtt-check-4 - MQTT broker CONNECT/CONNACK probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let connect: [u8; 19] = [
        0x10, 0x11, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02,
        0x00, 0x3c, 0x00, 0x05, 0x41, 0x4c, 0x6d, 0x61, 0x70,
    ];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "mqtt-check: broker not reachable");
            return 0;
        }
    };
    let mut buf = [0u8; 64];
    let _ = &mut buf;
    if send_all(&mut s, &connect).is_err() {
        set_out(ctx, "mqtt-check: no CONNACK");
        return 0;
    }
    let resp = recv_all(&mut s, 64);
    drop(s);
    if resp.len() < 4 {
        set_out(ctx, "mqtt-check: no CONNACK");
        return 0;
    }
    let suffix = if resp[0] == 0x20 && resp[3] == 0 {
        " (accepted, no auth; verify)"
    } else {
        ""
    };
    set_out(
        ctx,
        &format!(
            "mqtt-check: CONNACK type=0x{:02x} rc={}{}",
            resp[0], resp[3], suffix
        ),
    );
    0
}
