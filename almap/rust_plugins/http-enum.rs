/* http-enum - enumerate common web directories and files. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/admin/", "/administrator/", "/login", "/wp-admin/", "/wp-login.php",
        "/phpmyadmin/", "/server-status", "/server-info", "/.git/HEAD",
        "/.svn/entries", "/backup/", "/uploads/", "/cgi-bin/", "/api/",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/health",
    ];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) => r,
            None => continue,
        };
        let code = http_status(&resp);
        if !resp.is_empty() && code != 404 && code != 400 {
            if found == 0 {
                out.push_str("http-enum: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{} [{}]", path, code));
            found += 1;
        }
    }
    if found == 0 {
        out.push_str("http-enum: no common paths found");
    }
    set_out(ctx, &out);
    0
}
