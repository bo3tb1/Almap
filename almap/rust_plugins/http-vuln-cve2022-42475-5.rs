/* http-vuln-cve2022-42475-5 - Fortinet CVE-2022-42475 login probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/remote/login", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-42475-5: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Forti") {
    set_out(ctx, &format!("http-vuln-cve2022-42475-5: detected (HTTP {})", http_status(&resp)));
} else {
    set_out(ctx, &format!("http-vuln-cve2022-42475-5: not detected (HTTP {})", http_status(&resp)));
}
0
}
