/* iot-iec104-start-5 - IEC 60870-5-104 STARTDT probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 6] = [0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("iot-iec104-start-5: TCP {} not reachable", unsafe { (*ctx).port }));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "iot-iec104-start-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-iec104-start-5: no response");
        return 0;
    }
    if buf.len() >= 6 && buf[0] == 0x68 {
        set_out(ctx, &format!("iot-iec104-start-5: expected reply seen ({} bytes)", buf.len()));
    } else {
        set_out(ctx, &format!("iot-iec104-start-5: unexpected reply ({} bytes)", buf.len()));
    }
    0
}
