/* http-vuln-cve2023-20198-5 - Cisco IOS XE CVE-2023-20198 probe */
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
        "GET",
        "/webui/logoutconfirm.html?logon_hash=1",
        None,
        "",
        "",
        None,
        4096,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2023-20198-5: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "logoutconfirm") {
        set_out(ctx, &format!("http-vuln-cve2023-20198-5: detected (HTTP {})", code));
    } else {
        set_out(ctx, &format!("http-vuln-cve2023-20198-5: not detected (HTTP {})", code));
    }
    0
}
