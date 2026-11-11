/* http-webdav-scan-2 - enumerate WebDAV capabilities */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut out = String::new();
    let mut found = 0usize;
    if let Some(resp) = http_request(ctx, "OPTIONS", "/", None, "", "", None, 8192) {
        if contains_ci(&resp, "DAV") {
            out.push_str("WebDAV: OPTIONS advertises DAV");
            found += 1;
        }
    }
    if let Some(resp) = http_request(ctx, "PROPFIND", "/", None, "Depth: 0\r\n", "", None, 8192) {
        let code = http_status(&resp);
        if code == 207 || code == 200 {
            if found > 0 { out.push_str("; "); } else { out.push_str("WebDAV: "); }
            out.push_str(&format!("PROPFIND HTTP {}", code));
            found += 1;
        }
    }
    if found == 0 { set_out(ctx, "WebDAV: not enabled"); }
    else { set_out(ctx, &out); }
    0
}
