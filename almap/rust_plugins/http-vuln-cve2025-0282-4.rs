/* http-vuln-cve2025-0282-4 - Ivanti Connect Secure stack probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/dana-na/auth/url_default/welcome.cgi", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2025-0282-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Ivanti") {
    set_out(ctx, &format!("VULNERABLE: /dana-na/auth/url_default/welcome.cgi [{}] (CVE-2025-0282)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2025-0282 (/dana-na/auth/url_default/welcome.cgi [{}])", http_status(&resp)));
}
0
}
