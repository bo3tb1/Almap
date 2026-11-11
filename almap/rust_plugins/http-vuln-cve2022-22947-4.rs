/* http-vuln-cve2022-22947-4 - Spring Cloud Gateway SpEL probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/actuator/gateway/routes", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-22947-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Spring") {
    set_out(ctx, &format!("VULNERABLE: /actuator/gateway/routes [{}] (CVE-2022-22947)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2022-22947 (/actuator/gateway/routes [{}])", http_status(&resp)));
}
0
}
