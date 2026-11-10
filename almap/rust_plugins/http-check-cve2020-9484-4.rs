/* http-check-cve2020-9484-4 - Apache Tomcat session persistence deserialization
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
    let resp = match http_request(ctx, "GET", "/", None, "Cookie: JSESSIONID=../../../../../tmp/probe\r\n", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-check-cve2020-9484-4: no HTTP response");
            return 0;
        }
    };
    set_out(ctx, &format!("probe sent: GET / [{}] (CVE-2020-9484; verify out-of-band)", http_status(&resp)));
    0
}
