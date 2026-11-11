/* mqtt-topics-4 - MQTT wildcard SUBSCRIBE probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let connect: [u8; 19] = [
        0x10, 0x11, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02,
        0x00, 0x3c, 0x00, 0x05, 0x41, 0x4c, 0x6d, 0x61, 0x70,
    ];
    /* SUBSCRIBE packet id=1 to topic "#" qos0 */
    let sub: [u8; 8] = [0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 0x23, 0x00];

    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "mqtt-topics: no CONNACK");
            return 0;
        }
    };
    if send_all(&mut s, &connect).is_err() {
        set_out(ctx, "mqtt-topics: no CONNACK");
        return 0;
    }
    let connack = recv_all(&mut s, 64);
    if connack.len() < 4 {
        drop(s);
        set_out(ctx, "mqtt-topics: no CONNACK");
        return 0;
    }
    if send_all(&mut s, &sub).is_err() {
        drop(s);
        set_out(ctx, "mqtt-topics: wildcard subscribe refused");
        return 0;
    }
    let resp = recv_all(&mut s, 64);
    drop(s);
    if resp.len() >= 4 && resp[0] == 0x90 {
        set_out(ctx, "mqtt-topics: SUBACK for '#' (anon subscribe allowed; verify)");
    } else {
        set_out(ctx, "mqtt-topics: wildcard subscribe refused");
    }
    0
}
