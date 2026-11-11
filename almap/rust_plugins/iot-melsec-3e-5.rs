/* iot-melsec-3e-5 - Mitsubishi MELSEC 3E frame probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 20] = [0x50, 0x00, 0x00, 0xff, 0xff, 0x03, 0x00, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("iot-melsec-3e-5: TCP {} not reachable", unsafe { (*ctx).port }));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "iot-melsec-3e-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-melsec-3e-5: no response");
        return 0;
    }
    if buf.len() >= 2 && buf[0] == 0xd0 {
        set_out(ctx, &format!("iot-melsec-3e-5: expected reply seen ({} bytes)", buf.len()));
    } else {
        set_out(ctx, &format!("iot-melsec-3e-5: unexpected reply ({} bytes)", buf.len()));
    }
    0
}
