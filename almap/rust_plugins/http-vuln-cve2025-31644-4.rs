/* http-vuln-cve2025-31644-4 - Cisco web UI command injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/webui/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2025-31644-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Cisco") {
    set_out(ctx, &format!("VULNERABLE: /webui/ [{}] (CVE-2025-31644)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2025-31644 (/webui/ [{}])", http_status(&resp)));
}
0
}
