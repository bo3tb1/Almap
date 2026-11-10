/* http-drupal-enum - enumerate Drupal version and common paths */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/CHANGELOG.txt", "/user/login", "/node/1", "/install.php",
        "/update.php", "/sites/default/settings.php", "/robots.txt",
    ];
    let mut out = String::new();
    let mut ver = String::new();
    let mut found = 0usize;
    if !valid(ctx) { return 1; }
    for (i, path) in paths.iter().enumerate() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code == 404 { continue; }
        let body = http_body(&resp);
        if i == 0 && ver.is_empty() {
            if let Some(pos) = body.find("Drupal ") {
                let tail = &body[pos + 7..];
                ver = tail.split_whitespace().next().unwrap_or("").to_string();
            }
        }
        if code >= 200 && code < 500 {
            if found == 0 { out.push_str("Drupal: "); } else { out.push_str(", "); }
            out.push_str(path);
            found += 1;
        }
    }
    if !ver.is_empty() { out.push_str(&format!(" version {}", ver)); }
    if found == 0 { set_out(ctx, "Drupal: not detected"); } else { set_out(ctx, &out); }
    0
}
