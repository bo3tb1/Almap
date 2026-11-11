/* mqtt-version-4 - MQTT protocol-level acceptance probe */
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
            set_out(ctx, "mqtt-version: no response to MQTT 3.1.1 CONNECT");
            return 0;
        }
    };
    if send_all(&mut s, &connect).is_err() {
        set_out(ctx, "mqtt-version: no response to MQTT 3.1.1 CONNECT");
        return 0;
    }
    let resp = recv_all(&mut s, 64);
    drop(s);
    if resp.len() < 4 {
        set_out(ctx, "mqtt-version: no response to MQTT 3.1.1 CONNECT");
        return 0;
    }
    let verb = if resp[3] == 1 {
        "rejected proto level for"
    } else {
        "answered"
    };
    set_out(
        ctx,
        &format!("mqtt-version: broker {} MQTT 3.1.1 (rc={})", verb, resp[3]),
    );
    0
}
