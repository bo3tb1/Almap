/* http-server-headers - send HEAD / and extract the Server header. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "HEAD", "/", None, "", "", None, 3072) {
        Some(r) => r,
        None => return 1,
    };
    if resp.is_empty() {
        return 0;
    }
    if let Some(server) = http_header(&resp, "Server") {
        set_out(ctx, &format!("Server: {}", server));
    }
    0
}
