/* http-vuln-cve2023-3519-4 - Citrix ADC unauthenticated RCE probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/vpn/../vpns/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2023-3519-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Citrix") {
    set_out(ctx, &format!("VULNERABLE: /vpn/../vpns/ [{}] (CVE-2023-3519)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2023-3519 (/vpn/../vpns/ [{}])", http_status(&resp)));
}
0
}
