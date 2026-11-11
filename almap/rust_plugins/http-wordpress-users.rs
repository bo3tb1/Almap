/* http-wordpress-users - enumerate WordPress REST API users */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
fn wp_users(ctx: *mut AlScriptContext, body: &str) {
        let mut count = 0usize;
        let mut out = String::new();
        let mut rest = body;
        while let Some(p) = rest.find("\"slug\":\"") {
            let s = &rest[p + 8..];
            if let Some(e) = s.find('"') {
                let user = &s[..e];
                if !user.is_empty() {
                    if count > 0 { out.push_str(", "); }
                    out.push_str(user);
                    count += 1;
                }
                rest = &s[e + 1..];
            } else {
                break;
            }
        }
        if count == 0 { set_out(ctx, "WordPress users: none disclosed"); }
        else { append_out(ctx, &out); }
    }
    let resp = http_request(ctx, "GET", "/wp-json/wp/v2/users", None, "", "", None, 8192)
        .unwrap_or_default();
    if !resp.is_empty() && http_status(&resp) == 200 {
        set_out(ctx, "WordPress users: ");
        wp_users(ctx, http_body(&resp));
        return 0;
    }
    set_out(ctx, "WordPress users: ");
    let mut found = 0usize;
    for i in 1..=5 {
        let path = format!("/?author={}", i);
        if let Some(r) = http_request(ctx, "GET", &path, None, "", "", None, 8192) {
            if let Some(loc) = http_header(&r, "Location") {
                if found == 0 { set_out(ctx, "WordPress users: "); }
                else { append_out(ctx, ", "); }
                append_out(ctx, &loc);
                found += 1;
            }
        }
    }
    if found == 0 { set_out(ctx, "WordPress users: none disclosed"); }
    0
}
