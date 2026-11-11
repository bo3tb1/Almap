/* http-vuln-cve2015-1635-3 - IIS HTTP.sys Range header probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut code: i32 = 0;
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "Range: bytes=0-18446744073709551615\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2015-1635-3: no HTTP response"); return 0; }
};
code = http_status(&resp);
if (true && (code == 416 || code == 200 || code == 206)) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2015-1635 HTTP.sys (HTTP {})", code));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2015-1635 (HTTP {})", code));
}
0
}
