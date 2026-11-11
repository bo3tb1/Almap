/* http-vuln-cve2011-3192-3 - Apache Range header DoS probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut code: i32 = 0;
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "Range: bytes=0-1,0-1,0-1,0-1,0-1,0-1,0-1,0-1\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2011-3192-3: no HTTP response"); return 0; }
};
code = http_status(&resp);
if (true && (code == 206 || code == 200)) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2011-3192 Apache Range DoS (HTTP {})", code));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2011-3192 (HTTP {})", code));
}
0
}
