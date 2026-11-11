/* http-vuln-cve2025-31644-4 - Cisco web UI command injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/webui/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2025-31644-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Cisco") {
        set_out(ctx, &format!("VULNERABLE: /webui/ [{}] (CVE-2025-31644)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2025-31644 (/webui/ [{}])", code));
    }
    0
}
