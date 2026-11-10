/* http-vuln-cve2021-34473-4 - CVE-2021-34473 Exchange probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/autodiscover/autodiscover.json?@test.com=/mapi/nspi", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2021-34473-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Exchange") {
        set_out(ctx, &format!("VULNERABLE: /autodiscover/autodiscover.json?@test.com=/mapi/nspi [{}] (CVE-2021-34473)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2021-34473 (/autodiscover/autodiscover.json?@test.com=/mapi/nspi [{}])", code));
    }
    0
}
