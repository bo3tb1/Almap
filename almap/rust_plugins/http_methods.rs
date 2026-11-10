/* http_methods - OPTIONS request and Allow header extraction */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, b"OPTIONS * HTTP/1.0\r\n\r\n").is_err() {
        return 1;
    }
    let raw = recv_all(&mut s, 8192);
    drop(s);
    if raw.is_empty() {
        return 0;
    }
    let resp = String::from_utf8_lossy(&raw).into_owned();
    if let Some(v) = http_header(&resp, "Allow") {
        set_out(ctx, &format!("Allow: {}", v));
    }
    0
}
