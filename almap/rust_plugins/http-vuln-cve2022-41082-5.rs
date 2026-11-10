/* http-vuln-cve2022-41082-5 - Exchange ProxyShell CVE-2022-41082 probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(
        ctx,
        "POST",
        "/autodiscover/autodiscover.json?@foo.com/mapi/emsmdb/?&Email=autodiscover/autodiscover.json%3F@foo.com",
        None,
        "",
        "",
        None,
        4096,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2022-41082-5: no HTTP response");
            return 0;
        }
    };
    set_out(
        ctx,
        &format!(
            "http-vuln-cve2022-41082-5: HTTP {}, {} bytes",
            http_status(&resp),
            resp.len()
        ),
    );
    0
}
