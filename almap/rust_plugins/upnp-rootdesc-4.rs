/* upnp-rootdesc-4 - UPnP device description (rootDesc.xml) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/rootDesc.xml", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("upnp-rootdesc-4: no HTTP response on port {}", port));
            return 0;
        }
    };
    let code = http_status(&resp);
    let suffix = if code == 200 { " (open; verify)" } else { "" };
    set_out(ctx, &format!("upnp-rootdesc-4: GET /rootDesc.xml [{}]{}", code, suffix));
    0
}
