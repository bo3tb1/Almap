/* http-vuln-cve2013-0156-3 - Rails XML parameter parsing probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut code: i32 = 0;
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "POST", "/", None, "\r\n", "<?xml version=\"1.0\"?><hash><foo type=\"yaml\">--- !ruby/object:Object {}</foo></hash>", Some("application/xml"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2013-0156-3: no HTTP response"); return 0; }
};
code = http_status(&resp);
if (true && (code == 200 || code == 500)) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2013-0156 Rails XML (HTTP {})", code));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2013-0156 (HTTP {})", code));
}
0
}
