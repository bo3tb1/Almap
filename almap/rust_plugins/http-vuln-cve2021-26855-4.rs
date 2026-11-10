/* http-vuln-cve2021-26855-4 - CVE-2021-26855 Exchange probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/owa/auth/logon.aspx", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2021-26855-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Exchange") {
        set_out(ctx, &format!("VULNERABLE: /owa/auth/logon.aspx [{}] (CVE-2021-26855)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2021-26855 (/owa/auth/logon.aspx [{}])", code));
    }
    0
}
