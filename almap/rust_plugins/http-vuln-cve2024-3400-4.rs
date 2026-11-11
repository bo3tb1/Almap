/* http-vuln-cve2024-3400-4 - PAN-OS GlobalProtect command injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/ssl-vpn/hipreport.esp", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2024-3400-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "GlobalProtect") {
    set_out(ctx, &format!("VULNERABLE: /ssl-vpn/hipreport.esp [{}] (CVE-2024-3400)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2024-3400 (/ssl-vpn/hipreport.esp [{}])", http_status(&resp)));
}
0
}
