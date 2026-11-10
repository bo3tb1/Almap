/* http-favicon-3 - fetch the site favicon. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = http_request(ctx, "GET", "/favicon.ico", None, "", "", None, 8192).unwrap_or_default();
    if !resp.is_empty() && http_status(&resp) == 200 {
        set_out(ctx, &format!("favicon: present ({} response bytes)", resp.len()));
    } else {
        set_out(ctx, &format!("favicon: not found (HTTP {})", http_status(&resp)));
    }
    0
}
