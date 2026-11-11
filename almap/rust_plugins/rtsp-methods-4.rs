/* rtsp-methods-4 - RTSP OPTIONS probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let ip = ip_text(ctx);
    let port = unsafe { (*ctx).port };
    let req = format!("OPTIONS rtsp://{}:{}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: ALmap\r\n\r\n", ip, port);
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "rtsp-methods-4: not reachable");
            return 0;
        }
    };
    let sent = send_all(&mut s, req.as_bytes()).is_ok();
    let resp = if sent { recv_all(&mut s, 2048) } else { Vec::new() };
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "rtsp-methods-4: no RTSP reply");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    let show: String = cleaned.chars().take(200).collect();
    set_out(ctx, &format!("rtsp-methods-4: {}", show));
    0
}
