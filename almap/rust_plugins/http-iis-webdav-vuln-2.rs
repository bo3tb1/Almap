/* http-iis-webdav-vuln-2 - check IIS WebDAV methods */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "OPTIONS", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => String::new(),
    };
    if !resp.is_empty() && (contains_ci(&resp, "DAV:") || contains_ci(&resp, "PROPFIND")) {
        set_out(ctx, "potentially vulnerable: IIS WebDAV enabled");
    } else {
        set_out(ctx, &format!(
            "not vulnerable: IIS WebDAV not detected (HTTP {})",
            http_status(&resp)));
    }
    0
}
