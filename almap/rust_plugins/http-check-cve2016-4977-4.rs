/* http-check-cve2016-4977-4 - Spring Security OAuth2 SpEL injection * (CVE detection probe; benign request, verify out-of-band). * Use only on networks you own or have pe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/oauth/authorize?response_type=%24%7B1%2B1%7D", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-check-cve2016-4977-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: GET /oauth/authorize?response_type={}7B... [{}] (CVE2016-4977; verify out-of-band)", http_status(&resp), 0));
0
}
