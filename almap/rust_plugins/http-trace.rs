/* http-trace - HTTP TRACE method check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "TRACE", "/", None,
                                  "X-Almap-Trace: trace-test\r\n", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "TRACE: no response"); return 0; }
    };
    let code = http_status(&resp);
    if code == 200 && (contains_ci(&resp, "TRACE /") || contains_ci(&resp, "X-Almap-Trace")) {
        set_out(ctx, &format!("TRACE enabled (HTTP {})", code));
    } else if code == 405 || code == 501 {
        set_out(ctx, &format!("TRACE disabled (HTTP {})", code));
    } else {
        set_out(ctx, &format!("TRACE not confirmed (HTTP {})", code));
    }
    0
}
