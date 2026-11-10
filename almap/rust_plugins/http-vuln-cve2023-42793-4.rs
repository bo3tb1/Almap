/* http-vuln-cve2023-42793-4 - TeamCity auth bypass RCE probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/app/rest/server", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2023-42793-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "TeamCity") {
    set_out(ctx, &format!("VULNERABLE: /app/rest/server [{}] (CVE-2023-42793)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2023-42793 (/app/rest/server [{}])", http_status(&resp)));
}
0
}
