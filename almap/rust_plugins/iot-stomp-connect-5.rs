/* iot-stomp-connect-5 - STOMP CONNECT probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 40] = [0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x0a, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x2d, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x31, 0x2e, 0x32, 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x61, 0x6c, 0x6d, 0x61, 0x70, 0x0a, 0x0a, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("iot-stomp-connect-5: TCP {} not reachable", unsafe { (*ctx).port }));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "iot-stomp-connect-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-stomp-connect-5: no response");
        return 0;
    }
    let text = clean(&String::from_utf8_lossy(&buf));
    if contains_ci(&text, "CONNECTED") {
        set_out(ctx, "iot-stomp-connect-5: detected");
    } else {
        set_out(ctx, "iot-stomp-connect-5: not detected");
    }
    0
}
