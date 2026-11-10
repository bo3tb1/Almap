/* http-check-cve2018-1273-4 - Spring Data Commons SpEL injection
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
    let resp = match http_request(ctx, "POST", "/users", None, "", "username%5B%23this.getClass%28%29%5D=x&password=x&repeatedPassword=x", Some("application/x-www-form-urlencoded"), 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-check-cve2018-1273-4: no HTTP response");
            return 0;
        }
    };
    set_out(ctx, &format!("probe sent: POST /users [{}] (CVE2018-1273; verify out-of-band)", http_status(&resp)));
    0
}
