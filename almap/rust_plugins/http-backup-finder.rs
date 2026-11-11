/* http-backup-finder - look for common web backup archives */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/www.zip",
        "/website.zip", "/site.zip", "/html.zip", "/public_html.zip",
        "/index.php.bak", "/index.html.bak", "/db.sql", "/dump.sql",
        "/backup.sql", "/wp-content/backup.zip",
    ];
    let mut out = String::new();
    let mut found = 0usize;
    if !valid(ctx) { return 1; }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        let body = http_body(&resp);
        if code >= 200 && code < 300 && !contains_ci(body, "<html")
            && !contains_ci(body, "not found")
        {
            if found == 0 { out.push_str("backup files: "); } else { out.push_str(", "); }
            out.push_str(&format!("{} ({} bytes)", path, resp.len()));
            found += 1;
        }
    }
    if found == 0 { set_out(ctx, "backup files: none found"); } else { set_out(ctx, &out); }
    0
}
