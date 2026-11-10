/* http-vuln-cve2022-22947-4 - CVE-2022-22947 Spring Cloud Gateway probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/actuator/gateway/routes", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2022-22947-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Spring") {
        set_out(ctx, &format!("VULNERABLE: /actuator/gateway/routes [{}] (CVE-2022-22947)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2022-22947 (/actuator/gateway/routes [{}])", code));
    }
    0
}
