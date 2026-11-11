/* http-cookie-flags-3 - check cookie HttpOnly and Secure flags. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "HTTP cookie flags: no response"); return 0; }
};
if !contains_ci(&resp, "set-cookie:") {
    set_out(ctx, "HTTP cookie flags: no cookies set");
    return 0;
}
set_out(ctx, &format!("HTTP cookie flags: HttpOnly={} Secure={}", if contains_ci(&resp, "httponly") { "yes" } else { "no" }, if contains_ci(&resp, "secure") { "yes" } else { "no" }));
0
}
