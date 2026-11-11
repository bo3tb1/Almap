/* mqtt-connack-4 - MQTT CONNACK return-code decoder */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let connect: [u8; 19] = [
        0x10, 0x11, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02,
        0x00, 0x3c, 0x00, 0x05, 0x41, 0x4c, 0x6d, 0x61, 0x70,
    ];
    let rc = ["accepted", "bad proto version", "id rejected",
              "server unavailable", "bad user/pass", "not authorized"];
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => { set_out(ctx, "mqtt-connack: no response"); return 0; }
    };
    if send_all(&mut s, &connect).is_err() {
        set_out(ctx, "mqtt-connack: no response");
        return 0;
    }
    let r = recv_all(&mut s, 64);
    if r.len() < 4 {
        set_out(ctx, "mqtt-connack: no response");
        return 0;
    }
    let name = if (r[3] as usize) < rc.len() { rc[r[3] as usize] } else { "unknown" };
    set_out(ctx, &format!("mqtt-connack: rc={} ({})", r[3], name));
    0
}
