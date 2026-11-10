/* http-robots-3 - fetch and display robots.txt. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut body = String::new();
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/robots.txt", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, &format!("robots.txt: not found (HTTP {})", http_status(&resp))); return 0; }
};
if (false || http_status(&resp) >= 400) {
    set_out(ctx, &format!("robots.txt: not found (HTTP {})", http_status(&resp)));
    return 0;
}
body = http_body(&resp).to_string();
set_out(ctx, &format!("robots.txt: {}", body));
0
}
