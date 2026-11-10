/* http-headers-3 - report security-relevant HTTP headers. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "HTTP headers: no response");
            return 0;
        }
    };
    let mut out = String::new();
    let mut found = 0;
    if let Some(v) = http_header(&resp, "Server") {
        out.push_str(&format!("Server: {}", v));
        found += 1;
    }
    if let Some(v) = http_header(&resp, "X-Powered-By") {
        out.push_str(&format!("{}X-Powered-By: {}", if found > 0 { "; " } else { "" }, v));
        found += 1;
    }
    if let Some(v) = http_header(&resp, "Content-Type") {
        out.push_str(&format!("{}Content-Type: {}", if found > 0 { "; " } else { "" }, v));
        found += 1;
    }
    if let Some(v) = http_header(&resp, "X-Frame-Options") {
        out.push_str(&format!("{}X-Frame-Options: {}", if found > 0 { "; " } else { "" }, v));
        found += 1;
    }
    if found == 0 {
        set_out(ctx, "HTTP headers: none disclosed");
    } else {
        set_out(ctx, &out);
    }
    0
}
