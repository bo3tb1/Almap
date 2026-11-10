/* http-vuln-cve2011-3192-3 - CVE-2011-3192 Apache Range DoS probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None,
        "Range: bytes=0-1,0-1,0-1,0-1,0-1,0-1,0-1,0-1\r\n", "", None, 4096) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && (code == 206 || code == 200) {
        set_out(ctx, &format!(
            "potentially vulnerable: CVE-2011-3192 Apache Range DoS (HTTP {})", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2011-3192 (HTTP {})", code));
    }
    0
}
