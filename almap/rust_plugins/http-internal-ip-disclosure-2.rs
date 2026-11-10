/* http-internal-ip-disclosure-2 - look for private IPs in the response. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut body = String::new();
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "internal IP disclosure: no response"); return 0; }
};
body = http_body(&resp).to_string();
if (contains_ci(&body, "10.") || contains_ci(&body, "192.168.") || contains_ci(&body, "172.16.")) {
    set_out(ctx, "potentially vulnerable: private IP address disclosed");
} else {
    set_out(ctx, "not vulnerable: no private IP disclosed");
}
0
}
