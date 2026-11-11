/* svc-nexus-5 - Nexus repository status probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/service/rest/v1/status", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "svc-nexus-5: no HTTP response"); return 0; }
};
set_out(ctx, &format!("svc-nexus-5: HTTP {}, {} bytes", http_status(&resp), resp.len()));
0
}
