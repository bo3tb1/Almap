/* http-dombased-xss-2 - look for DOM XSS sinks in the landing page. */
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
            set_out(ctx, "DOM XSS: no response");
            return 0;
        }
    };
    let body = http_body(&resp);
    if contains_ci(body, "document.write") || contains_ci(body, "innerhtml") || contains_ci(body, "location.hash") {
        set_out(ctx, "potentially vulnerable: DOM XSS sink detected");
    } else {
        set_out(ctx, "not vulnerable: no DOM XSS sink found");
    }
    0
}
