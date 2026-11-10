/* http-svn-enum - Subversion metadata exposure probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/.svn/entries", "/.svn/wc.db", "/.svn/all-wcprops",
        "/.svn/prop-base/", "/.svn/text-base/", "/.svn/format",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let body = http_body(&resp);
        if http_status(&resp) == 200
            && (body.contains("svn") || body.contains("dir")
                || body.contains("SQLite") || body.contains("12"))
        {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "svn exposed: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "svn exposed: no");
    }
    0
}
