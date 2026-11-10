/* http-trace-2 - HTTP TRACE method check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "TRACE", "/", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => String::new(),
    };
    if !resp.is_empty() && http_status(&resp) == 200 && contains_ci(&resp, "TRACE") {
        set_out(ctx, "VULNERABLE: HTTP TRACE method enabled");
    } else {
        set_out(ctx, &format!("not vulnerable: HTTP TRACE (HTTP {})", http_status(&resp)));
    }
    0
}
