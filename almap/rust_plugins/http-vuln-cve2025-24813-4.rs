/* http-vuln-cve2025-24813-4 - Tomcat partial PUT RCE probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/partial", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2025-24813-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Tomcat") {
    set_out(ctx, &format!("VULNERABLE: /partial [{}] (CVE-2025-24813)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2025-24813 (/partial [{}])", http_status(&resp)));
}
0
}
