/* http-vuln-cve2023-25690 - Apache mod_proxy request-smuggling probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut code: i32 = 0;
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "POST", "/", None, "Transfer-Encoding: chunked\r\n", "0\r\n\r\n", Some("application/x-www-form-urlencoded"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2023-25690: no HTTP response"); return 0; }
};
code = http_status(&resp);
if (true && (code == 200 || code == 400 || code == 411)) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2023-25690 Apache mod_proxy smuggling (HTTP {})", code));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2023-25690 (HTTP {})", code));
}
0
}
