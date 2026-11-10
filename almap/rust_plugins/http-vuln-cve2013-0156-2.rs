/* http-vuln-cve2013-0156-2 - http-vuln-cve2013-0156 - Rails XML parameter parsing probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "POST", "/", None, "\r\n", "<?xml version=\"1.0\"?><hash><foo type=\"yaml\">--- !ruby/object:Object {}</foo></hash>", Some("application/xml"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2013-0156-2: no HTTP response"); return 0; }
};
if (true && (http_status(&resp) == 200 || http_status(&resp) == 500)) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2013-0156 Rails XML (HTTP {})", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2013-0156 (HTTP {})", http_status(&resp)));
}
0
}
