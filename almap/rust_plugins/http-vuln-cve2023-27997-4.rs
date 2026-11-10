/* http-vuln-cve2023-27997-4 - Fortinet FortiGate XSSL probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/remote/login", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2023-27997-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Fortinet") {
    set_out(ctx, &format!("VULNERABLE: /remote/login [{}] (CVE-2023-27997)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2023-27997 (/remote/login [{}])", http_status(&resp)));
}
0
}
