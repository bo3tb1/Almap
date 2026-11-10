/* http-feed-2 - detect RSS and Atom feeds. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let paths = ["/feed", "/rss.xml", "/atom.xml"];
    let needles = ["<rss", "<rss", "<feed"];
    let mut out = String::new();
    let mut found = 0;
    for (p, needle) in paths.iter().zip(needles.iter()) {
        let resp = http_request(ctx, "GET", p, None, "", "", None, 8192).unwrap_or_default();
        if resp.is_empty() {
            continue;
        }
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), needle) {
            out.push_str(&format!("{}{} [{}]", if found == 0 { "feeds: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "feeds: no matching paths");
    } else {
        set_out(ctx, &out);
    }
    0
}
