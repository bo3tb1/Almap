/* http-vuln-cve2024-4577-3 - PHP-CGI Windows argument injection. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/?%ADd+allow_url_include%3d1", "/index.php?%ADd+allow_url_include%3d1", "/php-cgi/php-cgi.exe?%ADd+allow_url_include%3d1"];
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code != 404 && code != 400 {
            let prefix = if found == 0 { "CVE-2024-4577: " } else { ", " };
            append_out(ctx, &format!("{}{} [{}]", prefix, path, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CVE-2024-4577: no matching paths");
    }
    0
}
