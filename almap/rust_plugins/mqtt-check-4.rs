/* mqtt-check-4 - MQTT broker CONNECT/CONNACK probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, "mqtt-check: broker not reachable"); return 0; }
};
if send_all(&mut s, &[16, 17, 0, 4, 77, 81, 84, 84, 4, 2, 0, 60, 0, 5, 65, 76, 109, 97, 112]).is_err() {
    set_out(ctx, "mqtt-check-4: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "mqtt-check-4: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 0 && buf[0] == 32 {
    set_out(ctx, "mqtt-check: no CONNACK");
} else {
    set_out(ctx, &format!("mqtt-check: CONNACK type=0x{:02x} rc={}{}", rb[0], rb[3], if (rb[0] == 0x20 && rb[3] == 0) { " (accepted, no auth; verify)" } else { "" }));
}
0
}
