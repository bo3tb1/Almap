/* iot-dnp3-link-status-5 - DNP3 link-status probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 10] = [0x05, 0x64, 0x05, 0xc9, 0x01, 0x00, 0x00, 0x04, 0xe9, 0x21];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("iot-dnp3-link-status-5: TCP {} not reachable", unsafe { (*ctx).port }));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "iot-dnp3-link-status-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-dnp3-link-status-5: no response");
        return 0;
    }
    if buf.len() >= 2 && buf[0] == 0x05 && buf[1] == 0x64 {
        set_out(ctx, &format!("iot-dnp3-link-status-5: expected reply seen ({} bytes)", buf.len()));
    } else {
        set_out(ctx, &format!("iot-dnp3-link-status-5: unexpected reply ({} bytes)", buf.len()));
    }
    0
}
