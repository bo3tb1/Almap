/* http-options - send OPTIONS / and extract the Allow header. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "OPTIONS", "/", None, "", "", None, 3072) {
        Some(r) => r,
        None => return 1,
    };
    if resp.is_empty() {
        return 0;
    }
    if let Some(allow) = http_header(&resp, "Allow") {
        set_out(ctx, &format!("Allow: {}", allow));
    }
    0
}
