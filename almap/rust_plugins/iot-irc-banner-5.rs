/* iot-irc-banner-5 - IRC service banner probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 35] = [0x4e, 0x49, 0x43, 0x4b, 0x20, 0x61, 0x6c, 0x6d, 0x61, 0x70, 0x0d, 0x0a, 0x55, 0x53, 0x45, 0x52, 0x20, 0x61, 0x6c, 0x6d, 0x61, 0x70, 0x20, 0x30, 0x20, 0x2a, 0x20, 0x3a, 0x61, 0x6c, 0x6d, 0x61, 0x70, 0x0d, 0x0a];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("iot-irc-banner-5: TCP {} not reachable", unsafe { (*ctx).port }));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "iot-irc-banner-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-irc-banner-5: no response");
        return 0;
    }
    let text = clean(&String::from_utf8_lossy(&buf));
    let shown: String = text.chars().take(220).collect();
    set_out(ctx, &format!("iot-irc-banner-5: {}", shown));
    0
}
