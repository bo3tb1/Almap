/* http-vuln-cve2022-37042-4 - Zimbra SOAP auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/service/soap", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-37042-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Zimbra") {
    set_out(ctx, &format!("VULNERABLE: /service/soap [{}] (CVE-2022-37042)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2022-37042 (/service/soap [{}])", http_status(&resp)));
}
0
}
