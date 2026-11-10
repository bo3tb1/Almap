/* http-check-cve2017-8046-4 - Spring Data REST PATCH SpEL injection * (CVE detection probe; benign request, verify out-of-band). * Use only on networks you own or have pe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "PATCH", "/customers/1", None, "", "[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime)\",\"value\":\"x\"}]", Some("application/json-patch+json"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-check-cve2017-8046-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: PATCH /customers/1 [{}] (CVE2017-8046; verify out-of-band)", http_status(&resp)));
0
}
