/* http-vuln-cve2022-22963-4 - Spring Cloud Function SpEL probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/functionRouter", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-22963-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Spring") {
    set_out(ctx, &format!("VULNERABLE: /functionRouter [{}] (CVE-2022-22963)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2022-22963 (/functionRouter [{}])", http_status(&resp)));
}
0
}
