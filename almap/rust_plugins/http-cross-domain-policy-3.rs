/* http-cross-domain-policy-3 - check for a permissive crossdomain.xml. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut body = String::new();
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/crossdomain.xml", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-cross-domain-policy-3: no response"); return 0; }
};
body = http_body(&resp).to_string();
if contains_ci(&body, "allow-access-from domain=\"*\"") {
    set_out(ctx, "VULNERABLE: permissive cross-domain policy");
} else {
    set_out(ctx, &format!("not vulnerable: permissive cross-domain policy (HTTP {})", http_status(&resp)));
}
0
}
