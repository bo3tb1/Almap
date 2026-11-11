/* http-favicon-3 - fetch the site favicon. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/favicon.ico", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-favicon-3: no HTTP response"); return 0; }
};
if (true && http_status(&resp) == 200) {
    set_out(ctx, &format!("favicon: present ({} response bytes)", resp.len()));
} else {
    set_out(ctx, &format!("favicon: not found (HTTP {})", http_status(&resp)));
}
0
}
