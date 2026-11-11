/* http-vuln-cve2025-0108-4 - PAN-OS management auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/unauth/php/change_password.php", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2025-0108-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "PAN-OS") {
        set_out(ctx, &format!("VULNERABLE: /unauth/php/change_password.php [{}] (CVE-2025-0108)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2025-0108 (/unauth/php/change_password.php [{}])", code));
    }
    0
}
