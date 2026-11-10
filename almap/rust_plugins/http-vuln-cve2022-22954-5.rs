/* http-vuln-cve2022-22954-5 - VMware Workspace ONE CVE-2022-22954 probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/catalog-portal/ui/oauth/verify?error=${7*7}", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-22954-5: no HTTP response"); return 0; }
};
if contains_ci(&resp, "49") {
    set_out(ctx, &format!("http-vuln-cve2022-22954-5: detected (HTTP {})", http_status(&resp)));
} else {
    set_out(ctx, &format!("http-vuln-cve2022-22954-5: not detected (HTTP {})", http_status(&resp)));
}
0
}
