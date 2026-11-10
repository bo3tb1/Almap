/* http-enum-3 - enumerate common web paths. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let paths = ["/admin/", "/login", "/robots.txt"];
    let mut out = String::new();
    let mut found = 0;
    for p in paths {
        let resp = http_request(ctx, "GET", p, None, "", "", None, 8192).unwrap_or_default();
        if resp.is_empty() {
            continue;
        }
        let code = http_status(&resp);
        if code != 404 && code != 400 {
            out.push_str(&format!("{}{} [{}]", if found == 0 { "http-enum: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "http-enum: no matching paths");
    } else {
        set_out(ctx, &out);
    }
    0
}
