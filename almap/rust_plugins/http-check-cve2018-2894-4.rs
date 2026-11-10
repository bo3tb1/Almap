/* http-check-cve2018-2894-4 - Oracle WebLogic ws_utc config exposure
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
    let resp = match http_request(ctx, "GET", "/ws_utc/config.do", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-check-cve2018-2894-4: no HTTP response");
            return 0;
        }
    };
    set_out(ctx, &format!("probe sent: GET /ws_utc/config.do [{}] (CVE2018-2894; verify out-of-band)", http_status(&resp)));
    0
}
