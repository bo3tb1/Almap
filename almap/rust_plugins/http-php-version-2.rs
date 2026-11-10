/* http-php-version-2 - PHP version disclosure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET",
        "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "PHP version: no response"); return 0; }
    };
    if let Some(val) = http_header(&resp, "X-Powered-By") {
        set_out(ctx, &format!("PHP version: {}", val));
        return 0;
    }
    if contains_ci(http_body(&resp), "PHP Version") {
        set_out(ctx, "PHP version: phpinfo banner disclosed");
    } else {
        set_out(ctx, &format!("PHP version: not disclosed (HTTP {})", http_status(&resp)));
    }
    0
}
