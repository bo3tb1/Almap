/* http-headers-2 - report security-relevant HTTP headers */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "HTTP headers: no response"); return 0; }
    };
    let mut out = String::new();
    let mut found = 0usize;
    for header in ["Server", "X-Powered-By", "Content-Type", "X-Frame-Options"] {
        if let Some(val) = http_header(&resp, header) {
            if found == 0 {
                out.push_str(&format!("{}: {}", header, val));
            } else {
                out.push_str(&format!("; {}: {}", header, val));
            }
            found += 1;
        }
    }
    if found == 0 { set_out(ctx, "HTTP headers: none disclosed"); }
    else { set_out(ctx, &out); }
    0
}
