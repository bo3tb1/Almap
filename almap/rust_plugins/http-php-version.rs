/* http-php-version - detect PHP version from headers and probes */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut resp = http_request(ctx, "GET", "/", None, "", "", None, 8192).unwrap_or_default();
    if !resp.is_empty() {
        if let Some(val) = http_header(&resp, "X-Powered-By") {
            if contains_ci(&val, "PHP") {
                set_out(ctx, &format!("PHP version: {}", val));
                return 0;
            }
        }
    }
    resp = http_request(ctx, "GET", "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000",
                        None, "", "", None, 8192).unwrap_or_default();
    if !resp.is_empty() && contains_ci(http_body(&resp), "PHP") {
        let body = http_body(&resp);
        if let Some(p) = body.find("PHP Version") {
            let tail = body[p + 11..].trim_start_matches(|c: char| c == ' ' || c == ':' || c == '<' || c == '>');
            let ver = tail.split_whitespace().next().unwrap_or("");
            if !ver.is_empty() {
                set_out(ctx, &format!("PHP version: {}", ver));
                return 0;
            }
        }
    }
    resp = http_request(ctx, "GET", "/phpinfo.php", None, "", "", None, 8192).unwrap_or_default();
    if !resp.is_empty() && contains_ci(&resp, "PHP Version") {
        let body = http_body(&resp);
        let low = body.to_ascii_lowercase();
        if let Some(p) = low.find("php version") {
            let tail = body[p + 11..].trim_start_matches(|c: char| c == ' ' || c == ':' || c == '<' || c == '>');
            let ver = tail.split_whitespace().next().unwrap_or("");
            if !ver.is_empty() {
                set_out(ctx, &format!("PHP version: {}", ver));
                return 0;
            }
        }
    }
    set_out(ctx, "PHP version: not disclosed");
    0
}
