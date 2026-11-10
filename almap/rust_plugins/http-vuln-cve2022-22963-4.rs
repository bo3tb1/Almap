/* http-vuln-cve2022-22963-4 - CVE-2022-22963 Spring Cloud Function probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/functionRouter", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2022-22963-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Spring") {
        set_out(ctx, &format!("VULNERABLE: /functionRouter [{}] (CVE-2022-22963)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2022-22963 (/functionRouter [{}])", code));
    }
    0
}
