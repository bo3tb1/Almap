/* http-robots-2 - robots.txt disclosure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/robots.txt", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "robots.txt: not found (HTTP 0)");
            return 0;
        }
    };
    if http_status(&resp) >= 400 {
        set_out(ctx, &format!("robots.txt: not found (HTTP {})", http_status(&resp)));
        return 0;
    }
    let shown: String = http_body(&resp).chars().take(500).collect();
    set_out(ctx, &format!("robots.txt: {}", shown));
    0
}
