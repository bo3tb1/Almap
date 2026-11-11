/* http-vuln-cve2022-22965 - Spring4Shell class-loader probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut body = String::new();
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "POST", "/", None, "\r\n", "class.module.classLoader.resources.context.parent.pipeline.first.pattern=ALMAP", Some("application/x-www-form-urlencoded"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "CVE-2022-22965: no response"); return 0; }
};
body = http_body(&resp).to_string();
if (contains_ci(&body, "Whitelabel") || http_status(&resp) == 400 || http_status(&resp) == 500) {
    set_out(ctx, &format!("potentially vulnerable: CVE-2022-22965 Spring4Shell (HTTP {})", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2022-22965 Spring4Shell (HTTP {})", http_status(&resp)));
}
0
}
