/* http-vuln-cve2022-22960-5 - CVE-2022-22960 probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET",
        "/catalog-portal/ui/oauth/verify?error=almap", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2022-22960-5: no HTTP response"); return 0; }
    };
    set_out(ctx, &format!("http-vuln-cve2022-22960-5: HTTP {}, {} bytes",
                          http_status(&resp), resp.len()));
    0
}
