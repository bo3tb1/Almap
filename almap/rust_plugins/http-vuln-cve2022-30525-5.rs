/* http-vuln-cve2022-30525-5 - Zyxel CVE-2022-30525 endpoint probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/ztp/cgi-bin/handler", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2022-30525-5: no HTTP response");
            return 0;
        }
    };
    set_out(
        ctx,
        &format!(
            "http-vuln-cve2022-30525-5: HTTP {}, {} bytes",
            http_status(&resp),
            resp.len()
        ),
    );
    0
}
