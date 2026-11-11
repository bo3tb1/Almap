/* http-trace - check whether the HTTP TRACE method is enabled. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "TRACE", "/", None, "X-Almap-Trace: trace-test\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "TRACE: no response"); return 0; }
};
if (http_status(&resp) == 200 && (contains_ci(&resp, "TRACE /") || contains_ci(&resp, "X-Almap-Trace"))) {
    set_out(ctx, &format!("TRACE enabled (HTTP {})", http_status(&resp)));
} else {
    if (http_status(&resp) == 405 || http_status(&resp) == 501) {
        set_out(ctx, &format!("TRACE disabled (HTTP {})", http_status(&resp)));
    } else {
        set_out(ctx, &format!("TRACE not confirmed (HTTP {})", http_status(&resp)));
    }
    return 0;
}
0
}
