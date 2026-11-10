/* http-csrf-3 - look for forms without a CSRF token. */
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
            set_out(ctx, "HTTP CSRF: no response");
            return 0;
        }
    };
    let body = http_body(&resp);
    if contains_ci(body, "<form") && !contains_ci(body, "csrf") && !contains_ci(body, "token") {
        set_out(ctx, "potentially vulnerable: form without CSRF token");
    } else {
        set_out(ctx, "not vulnerable: no unprotected form found");
    }
    0
}
