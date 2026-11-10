/* http-vuln-cve2024-24919-4 - Check Point Quantum path traversal probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/clients/MyCRL", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2024-24919-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "root:") {
    set_out(ctx, &format!("VULNERABLE: /clients/MyCRL [{}] (CVE-2024-24919)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2024-24919 (/clients/MyCRL [{}])", http_status(&resp)));
}
0
}
