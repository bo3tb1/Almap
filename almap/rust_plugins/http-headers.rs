/* http-headers - dump the full HTTP response header block. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-headers: no response");
            return 0;
        }
    };
    let end = resp.find("\r\n\r\n").map(|i| i + 4)
        .or_else(|| resp.find("\n\n").map(|i| i + 2))
        .unwrap_or(resp.len());
    set_out(ctx, &resp[..end]);
    0
}
