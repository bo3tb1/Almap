/* http-wordpress-users - enumerate WordPress REST API users. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = http_request(ctx, "GET", "/wp-json/wp/v2/users", None, "", "", None, 8192) {
        if !resp.is_empty() && http_status(&resp) == 200 {
            set_out(ctx, "WordPress users: ");
            let body = http_body(&resp);
            let mut count = 0;
            let mut rest = body;
            while let Some(i) = rest.find("\"slug\":\"") {
                let s = &rest[i + 8..];
                if let Some(e) = s.find('"') {
                    let user = &s[..e];
                    if !user.is_empty() {
                        let prefix = if count == 0 { "" } else { ", " };
                        append_out(ctx, &format!("{}{}", prefix, user));
                        count += 1;
                    }
                    rest = &s[e + 1..];
                } else {
                    break;
                }
            }
            if count == 0 {
                set_out(ctx, "WordPress users: none disclosed");
            }
            return 0;
        }
    }
    let mut found = 0;
    for i in 1..=5 {
        let path = format!("/?author={}", i);
        if let Some(resp) = http_request(ctx, "GET", &path, None, "", "", None, 8192) {
            if !resp.is_empty() {
                if let Some(loc) = http_header(&resp, "Location") {
                    let prefix = if found == 0 { "WordPress users: " } else { ", " };
                    append_out(ctx, &format!("{}{}", prefix, loc));
                    found += 1;
                }
            }
        }
    }
    if found == 0 {
        set_out(ctx, "WordPress users: none disclosed");
    }
    0
}
