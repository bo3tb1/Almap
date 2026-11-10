/* prometheus-metrics-4 - Prometheus /metrics exposition * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/metrics", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, &format!("prometheus-metrics-4: no HTTP response on port {}", port)); return 0; }
};
set_out(ctx, &format!("prometheus-metrics-4: GET /metrics [{}]{}", http_status(&resp), if http_status(&resp) == 200 { " (open; verify)" } else { "" }));
0
}
