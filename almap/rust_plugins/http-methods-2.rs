/* http-methods-2 - report the Allow header from an OPTIONS request. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut allow = String::new();
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "OPTIONS", "/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "HTTP methods: no response"); return 0; }
};
allow = http_header(&resp, "Allow").unwrap_or_default();
if !allow.is_empty() {
    set_out(ctx, &format!("HTTP methods: {}", allow));
} else {
    set_out(ctx, &format!("HTTP methods: Allow not disclosed (HTTP {})", http_status(&resp)));
}
0
}
