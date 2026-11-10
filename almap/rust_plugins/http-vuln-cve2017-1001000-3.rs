/* http-vuln-cve2017-1001000-3 - CVE-2017-1001000 WordPress REST API */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/wp-json/wp/v2/posts/1", "/wp-json/wp/v2/users/1",
        "/?rest_route=/wp/v2/posts/1",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if contains_ci(http_body(&resp), "\"id\"") {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: CVE-2017-1001000 WordPress REST API");
    } else {
        append_out(ctx, " (CVE-2017-1001000 WordPress REST API)");
    }
    0
}
