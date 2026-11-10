/* http-vuln-cve2022-22965-4 - CVE-2022-22965 Spring4Shell probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2022-22965-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Spring") {
        set_out(ctx, &format!("VULNERABLE: / [{}] (CVE-2022-22965)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2022-22965 (/ [{}])", code));
    }
    0
}
