/* prometheus-targets-4 - Prometheus scrape targets API * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/api/v1/targets", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, &format!("prometheus-targets-4: no HTTP response on port {}", port)); return 0; }
};
set_out(ctx, &format!("prometheus-targets-4: GET /api/v1/targets [{}]{}", http_status(&resp), if http_status(&resp) == 200 { " (open; verify)" } else { "" }));
0
}
