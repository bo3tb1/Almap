/* http-vuln-cve2020-5902-4 - F5 BIG-IP TMUI RCE probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/tmui/login.jsp", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2020-5902-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "F5") {
    set_out(ctx, &format!("VULNERABLE: /tmui/login.jsp [{}] (CVE-2020-5902)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2020-5902 (/tmui/login.jsp [{}])", http_status(&resp)));
}
0
}
