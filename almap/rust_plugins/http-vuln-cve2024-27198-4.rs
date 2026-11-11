/* http-vuln-cve2024-27198-4 - JetBrains TeamCity auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/app/rest/users", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-27198-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "TeamCity") {
        set_out(ctx, &format!("VULNERABLE: /app/rest/users [{}] (CVE-2024-27198)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2024-27198 (/app/rest/users [{}])", code));
    }
    0
}
