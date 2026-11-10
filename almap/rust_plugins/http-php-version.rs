/* http-php-version - PHP version disclosure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    fn php_token(s: &str) -> Option<String> {
        let lower = s.to_ascii_lowercase();
        let pos = lower.find("php version")?;
        let mut rest = &s[pos + 11..];
        rest = rest.trim_start_matches(|c| c == ' ' || c == ':' || c == '<' || c == '>');
        let tok = rest.split_whitespace().next()?;
        if tok.is_empty() { None } else { Some(tok.to_string()) }
    }
    if let Some(resp) = http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        if let Some(val) = http_header(&resp, "X-Powered-By") {
            if contains_ci(&val, "PHP") {
                set_out(ctx, &format!("PHP version: {}", val));
                return 0;
            }
        }
    }
    if let Some(resp) = http_request(ctx, "GET",
        "/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000", None, "", "", None, 8192) {
        if contains_ci(http_body(&resp), "PHP") {
            if let Some(val) = php_token(http_body(&resp)) {
                set_out(ctx, &format!("PHP version: {}", val));
                return 0;
            }
        }
    }
    if let Some(resp) = http_request(ctx, "GET", "/phpinfo.php", None, "", "", None, 8192) {
        if contains_ci(&resp, "PHP Version") {
            if let Some(val) = php_token(http_body(&resp)) {
                set_out(ctx, &format!("PHP version: {}", val));
                return 0;
            }
        }
    }
    set_out(ctx, "PHP version: not disclosed");
    0
}
