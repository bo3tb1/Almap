/* http-check-cve2022-31813-4 - Apache httpd mod_proxy X-Forwarded-For drop * (CVE detection probe; benign request, verify out-of-band). * Use only on networks you own or h */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "X-Forwarded-For: 127.0.0.1\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-check-cve2022-31813-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: GET / [{}] (CVE-2022-31813; verify out-of-band)", http_status(&resp)));
0
}
