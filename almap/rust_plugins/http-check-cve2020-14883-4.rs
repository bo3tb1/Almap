/* http-check-cve2020-14883-4 - Oracle WebLogic console path traversal
 * (CVE detection probe; benign request, verify out-of-band).
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/console/css/%252e%252e%252fconsole.portal", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-check-cve2020-14883-4: no HTTP response");
            return 0;
        }
    };
    set_out(ctx, &format!("probe sent: GET /console/css/%252e%252e%252fconsole.p... [{}] (CVE2020-14883; verify out-of-band)", http_status(&resp)));
    0
}
