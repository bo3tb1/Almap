/* http_server_headers - Server header disclosure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "HEAD", "/", None, "", "", None, 3072) {
        Some(r) if !r.is_empty() => r,
        _ => return 0,
    };
    if let Some(server) = http_header(&resp, "Server") {
        set_out(ctx, &format!("Server: {}", server));
    }
    0
}
