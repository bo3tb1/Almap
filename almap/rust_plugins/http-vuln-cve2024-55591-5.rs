/* http-vuln-cve2024-55591-5 - Fortinet CVE-2024-55591 login probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/remote/login", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-55591-5: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Forti") {
        set_out(ctx, &format!("http-vuln-cve2024-55591-5: detected (HTTP {})", code));
    } else {
        set_out(ctx, &format!("http-vuln-cve2024-55591-5: not detected (HTTP {})", code));
    }
    0
}
