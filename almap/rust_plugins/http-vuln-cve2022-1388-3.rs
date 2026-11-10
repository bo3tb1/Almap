/* http-vuln-cve2022-1388-3 - F5 iControl REST auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut code: i32 = 0;
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "POST", "/mgmt/shared/authn/login", None, "\r\n", "{\"username\":\"admin\",\"password\":\"\"}", Some("application/json"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-1388-3: no HTTP response"); return 0; }
};
code = http_status(&resp);
if (true && (code == 200 || contains_ci(&resp, "token"))) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2022-1388 F5 iControl REST (HTTP {})", code));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2022-1388 (HTTP {})", code));
}
0
}
