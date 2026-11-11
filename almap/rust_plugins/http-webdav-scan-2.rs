/* http-webdav-scan-2 - enumerate WebDAV capabilities. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = http_request(ctx, "OPTIONS", "/", None, "", "", None, 8192) {
        if !resp.is_empty() && contains_ci(&resp, "DAV") {
            append_out(ctx, "WebDAV: OPTIONS advertises DAV");
            found += 1;
        }
    }
    if let Some(resp) = http_request(ctx, "PROPFIND", "/", None, "Depth: 0\r\n", "", None, 8192) {
        if !resp.is_empty() && (http_status(&resp) == 207 || http_status(&resp) == 200) {
            let prefix = if found != 0 { "; " } else { "WebDAV: " };
            append_out(ctx, &format!("{}PROPFIND HTTP {}", prefix, http_status(&resp)));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "WebDAV: not enabled");
    }
    0
}
