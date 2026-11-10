/* http-vuln-cve2021-31166-5 - CVE-2021-31166 HTTP.sys probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None,
                                  "Accept-Encoding: gzip, gzip\r\n", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2021-31166-5: no HTTP response"); return 0; }
    };
    set_out(ctx, &format!("http-vuln-cve2021-31166-5: HTTP {}, {} bytes",
                          http_status(&resp), resp.len()));
    0
}
