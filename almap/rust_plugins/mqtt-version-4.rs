/* mqtt-version-4 - MQTT protocol-level acceptance probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("mqtt-version-4: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[16, 17, 0, 4, 77, 81, 84, 84, 4, 2, 0, 60, 0, 5, 65, 76, 109, 97, 112]).is_err() {
    set_out(ctx, "mqtt-version-4: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "mqtt-version: no response to MQTT 3.1.1 CONNECT");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 3 && buf[3] == 1 {
    set_out(ctx, &format!("mqtt-version: broker {} MQTT 3.1.1 (rc={})", if rb[3] == 1 { "rejected proto level for" } else { "answered" }, rb[3]));
} else {
    set_out(ctx, "mqtt-version-4: unexpected reply");
}
0
}
