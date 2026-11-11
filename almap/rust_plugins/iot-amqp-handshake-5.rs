/* iot-amqp-handshake-5 - AMQP 0-9-1 protocol-header probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 8] = [0x41, 0x4d, 0x51, 0x50, 0x00, 0x00, 0x09, 0x01];
    if !valid(ctx) {
        return 1;
    }
    let port = unsafe { (*ctx).port };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("iot-amqp-handshake-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "iot-amqp-handshake-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-amqp-handshake-5: no response");
        return 0;
    }
    if buf.len() >= 4 && &buf[..4] == b"AMQP" {
        set_out(ctx, &format!("iot-amqp-handshake-5: expected reply seen ({} bytes)", buf.len()));
    } else {
        set_out(ctx, &format!("iot-amqp-handshake-5: unexpected reply ({} bytes)", buf.len()));
    }
    0
}
