/* kubelet-pods-4 - Kubelet read-only pods endpoint */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let port = unsafe { (*ctx).port };
    let resp = match http_request(ctx, "GET", "/pods", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, &format!("kubelet-pods-4: no HTTP response on port {}", port));
            return 0;
        }
    };
    let code = http_status(&resp);
    let suffix = if code == 200 { " (open; verify)" } else { "" };
    set_out(
        ctx,
        &format!("kubelet-pods-4: GET /pods [{}]{}", code, suffix),
    );
    0
}
