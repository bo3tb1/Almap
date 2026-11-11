/* iot-pjlink-info-5 - PJLink projector info probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 9] = [0x25, 0x31, 0x49, 0x4e, 0x46, 0x4f, 0x20, 0x3f, 0x0d];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("iot-pjlink-info-5: TCP {} not reachable", unsafe { (*ctx).port }));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "iot-pjlink-info-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-pjlink-info-5: no response");
        return 0;
    }
    let text = clean(&String::from_utf8_lossy(&buf));
    if contains_ci(&text, "%1INFO") {
        set_out(ctx, "iot-pjlink-info-5: detected");
    } else {
        set_out(ctx, "iot-pjlink-info-5: not detected");
    }
    0
}
