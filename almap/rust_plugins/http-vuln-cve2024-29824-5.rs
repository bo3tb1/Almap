/* http-vuln-cve2024-29824-5 - Ivanti EPM CVE-2024-29824 probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/WSUSWebService.asmx", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-29824-5: no HTTP response");
            return 0;
        }
    };
    set_out(
        ctx,
        &format!("http-vuln-cve2024-29824-5: HTTP {}, {} bytes", http_status(&resp), resp.len()),
    );
    0
}
