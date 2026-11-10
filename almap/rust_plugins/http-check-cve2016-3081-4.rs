/* http-check-cve2016-3081-4 - Apache Struts2 S2-032 dynamic method invocation * (CVE detection probe; benign request, verify out-of-band). * Use only on networks you own  */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/index.action?method:%23_memberAccess", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-check-cve2016-3081-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: GET /index.action?method:%23_memberAccess [{}] (CVE2016-3081; verify out-of-band)", http_status(&resp)));
0
}
