/* http-vuln-cve2024-53677-4 - Apache Struts file upload traversal probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/upload.action", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2024-53677-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Struts") {
    set_out(ctx, &format!("VULNERABLE: /upload.action [{}] (CVE-2024-53677)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2024-53677 (/upload.action [{}])", http_status(&resp)));
}
0
}
