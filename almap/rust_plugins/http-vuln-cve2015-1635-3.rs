/* http-vuln-cve2015-1635-3 - CVE-2015-1635 HTTP.sys Range probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None,
                                  "Range: bytes=0-18446744073709551615\r\n", "", None, 4096) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && (code == 416 || code == 200 || code == 206) {
        set_out(ctx, &format!(
            "potentially vulnerable: CVE-2015-1635 HTTP.sys (HTTP {})", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2015-1635 (HTTP {})", code));
    }
    0
}
