/* http_options - OPTIONS request and Allow header extraction */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "OPTIONS", "/", None, "", "", None, 3072) {
        Some(r) if !r.is_empty() => r,
        _ => return 0,
    };
    if let Some(allow) = http_header(&resp, "Allow") {
        set_out(ctx, &format!("Allow: {}", allow));
    }
    0
}
