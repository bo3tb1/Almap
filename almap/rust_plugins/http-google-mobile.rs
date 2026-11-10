/* http-google-mobile - detect Google mobile redirect/endpoint behaviour. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/", None, "User-Agent: Mozilla/5.0 (Linux; Android 10; Mobile)\r\n", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "google-mobile: no response");
            return 0;
        }
    };
    let body = http_body(&resp);
    if let Some(loc) = http_header(&resp, "Location") {
        if contains_ci(&loc, "google") || contains_ci(&loc, "/m/") || contains_ci(&loc, "mobile") {
            set_out(ctx, &format!("google-mobile: mobile redirect {}", loc));
            return 0;
        }
    }
    if contains_ci(body, "google") && contains_ci(body, "mobile") {
        set_out(ctx, "google-mobile: mobile Google page detected");
    } else {
        set_out(ctx, "google-mobile: no mobile Google behaviour detected");
    }
    0
}
