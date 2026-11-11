/* http-check-cve2017-12149-4 - JBoss ReadOnlyAccessFilter deserialization * (CVE detection probe; benign request, verify out-of-band). * Use only on networks you own or ha */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "POST", "/invoker/readonly", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-check-cve2017-12149-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: POST /invoker/readonly [{}] (CVE2017-12149; verify out-of-band)", http_status(&resp)));
0
}
