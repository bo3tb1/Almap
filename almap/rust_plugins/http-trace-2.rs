/* http-trace-2 - test whether the TRACE method is enabled. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "TRACE", "/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-trace-2: no HTTP response"); return 0; }
};
if (true && http_status(&resp) == 200 && contains_ci(&resp, "TRACE")) {
    set_out(ctx, "VULNERABLE: HTTP TRACE method enabled");
} else {
    set_out(ctx, &format!("not vulnerable: HTTP TRACE (HTTP {})", http_status(&resp)));
}
0
}
