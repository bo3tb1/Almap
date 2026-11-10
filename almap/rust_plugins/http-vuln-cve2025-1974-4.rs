/* http-vuln-cve2025-1974-4 - Ingress NGINX admission webhook probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "Admission-Review-API: true\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2025-1974-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: / [{}] (CVE-2025-1974; verify out-of-band)", http_status(&resp)));
0
}
