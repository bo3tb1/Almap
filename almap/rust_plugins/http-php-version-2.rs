/* http-php-version-2 - disclose the PHP version. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut val = String::new();
let mut body = String::new();
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "PHP version: no response"); return 0; }
};
val = http_header(&resp, "X-Powered-By").unwrap_or_default();
if !val.is_empty() {
    set_out(ctx, &format!("PHP version: {}", val));
    return 0;
}
body = http_body(&resp).to_string();
if contains_ci(&body, "PHP Version") {
    set_out(ctx, "PHP version: phpinfo banner disclosed");
} else {
    set_out(ctx, &format!("PHP version: not disclosed (HTTP {})", http_status(&resp)));
}
0
}
