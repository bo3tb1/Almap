/* http-vuln-cve2021-34473-4 - Exchange ProxyShell path confusion probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/autodiscover/autodiscover.json?@test.com=/mapi/nspi", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2021-34473-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Exchange") {
    set_out(ctx, &format!("VULNERABLE: /autodiscover/autodiscover.json?@test.com=/mapi/nspi [{}] (CVE-2021-34473)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2021-34473 (/autodiscover/autodiscover.json?@test.com=/mapi/nspi [{}])", http_status(&resp)));
}
0
}
