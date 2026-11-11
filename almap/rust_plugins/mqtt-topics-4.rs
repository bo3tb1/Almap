/* mqtt-topics-4 - MQTT wildcard SUBSCRIBE probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("mqtt-topics-4: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[16, 17, 0, 4, 77, 81, 84, 84, 4, 2, 0, 60, 0, 5, 65, 76, 109, 97, 112]).is_err() {
    set_out(ctx, "mqtt-topics-4: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "mqtt-topics-4: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 0 && buf[0] == 144 {
    set_out(ctx, "mqtt-topics: no CONNACK");
} else {
    set_out(ctx, "mqtt-topics: SUBACK for '#' (anon subscribe allowed; verify)");
}
0
}
