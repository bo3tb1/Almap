/* http-cross-domain-policy-2 - check for a permissive crossdomain.xml. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/crossdomain.xml", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-cross-domain-policy-2: no response");
            return 0;
        }
    };
    let body = http_body(&resp);
    if contains_ci(body, "allow-access-from domain=\"*\"") {
        set_out(ctx, "VULNERABLE: permissive cross-domain policy");
    } else {
        set_out(ctx, &format!("not vulnerable: permissive cross-domain policy (HTTP {})", http_status(&resp)));
    }
    0
}
