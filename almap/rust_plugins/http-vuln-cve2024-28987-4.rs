/* http-vuln-cve2024-28987-4 - SolarWinds Web Help Desk SSRF probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/SolarWinds/InformationService/v3/Json/Query", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2024-28987-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "SolarWinds") {
    set_out(ctx, &format!("VULNERABLE: /SolarWinds/InformationService/v3/Json/Query [{}] (CVE-2024-28987)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2024-28987 (/SolarWinds/InformationService/v3/Json/Query [{}])", http_status(&resp)));
}
0
}
