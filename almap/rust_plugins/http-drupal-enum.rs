/* http-drupal-enum - enumerate Drupal version and common paths. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let paths = ["/CHANGELOG.txt", "/user/login", "/node/1", "/install.php", "/update.php", "/sites/default/settings.php", "/robots.txt"];
    let mut out = String::new();
    let mut found = 0;
    let mut ver = String::new();
    for (i, p) in paths.iter().enumerate() {
        let resp = http_request(ctx, "GET", p, None, "", "", None, 8192).unwrap_or_default();
        if resp.is_empty() {
            continue;
        }
        let code = http_status(&resp);
        if code == 404 {
            continue;
        }
        let body = http_body(&resp);
        if i == 0 && ver.is_empty() {
            if let Some(pos) = body.find("Drupal ") {
                ver = body[pos + 7..].split_whitespace().next().unwrap_or("").to_string();
            }
        }
        if (200..500).contains(&code) {
            out.push_str(&format!("{}{}", if found == 0 { "Drupal: " } else { ", " }, p));
            found += 1;
        }
    }
    if !ver.is_empty() {
        out.push_str(&format!(" version {}", ver));
    }
    if found == 0 {
        set_out(ctx, "Drupal: not detected");
    } else {
        set_out(ctx, &out);
    }
    0
}
