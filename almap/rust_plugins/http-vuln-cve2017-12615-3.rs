/* http-vuln-cve2017-12615-3 - Tomcat PUT JSP probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut code: i32 = 0;
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "PUT", "/almap.jsp/", None, "\r\n", "<% out.println(\"ALMAP\"); %>", Some("text/plain"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2017-12615-3: no HTTP response"); return 0; }
};
code = http_status(&resp);
if (true && (code == 200 || code == 201 || code == 204)) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2017-12615 Tomcat PUT (HTTP {})", code));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2017-12615 (HTTP {})", code));
}
0
}
