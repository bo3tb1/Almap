/* http-vuln-cve2021-22893-4 - CVE-2021-22893 Pulse Secure probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/dana-na/auth/url_default/welcome.cgi", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2021-22893-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Pulse") {
        set_out(ctx, &format!("VULNERABLE: /dana-na/auth/url_default/welcome.cgi [{}] (CVE-2021-22893)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2021-22893 (/dana-na/auth/url_default/welcome.cgi [{}])", code));
    }
    0
}
