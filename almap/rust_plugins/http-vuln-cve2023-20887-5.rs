/* http-vuln-cve2023-20887-5 - VMware Aria CVE-2023-20887 probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/SAAS/API/1.0/GET/metadata/", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2023-20887-5: no HTTP response");
            return 0;
        }
    };
    set_out(
        ctx,
        &format!(
            "http-vuln-cve2023-20887-5: HTTP {}, {} bytes",
            http_status(&resp),
            resp.len()
        ),
    );
    0
}
