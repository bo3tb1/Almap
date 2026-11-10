/* http-svn-enum - detect exposed Subversion metadata */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/.svn/entries", "/.svn/wc.db", "/.svn/all-wcprops",
        "/.svn/prop-base/", "/.svn/text-base/", "/.svn/format",
    ];
    let mut out = String::new();
    let mut found = 0usize;
    if !valid(ctx) { return 1; }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let body = http_body(&resp);
        if http_status(&resp) == 200
            && (body.contains("svn") || body.contains("dir")
                || body.contains("SQLite") || body.contains("12"))
        {
            if found == 0 { out.push_str("svn exposed: "); } else { out.push_str(", "); }
            out.push_str(path);
            found += 1;
        }
    }
    if found == 0 { set_out(ctx, "svn exposed: no"); } else { set_out(ctx, &out); }
    0
}
