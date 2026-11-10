/* http-vuln-cve2019-11043 - CVE-2019-11043 PHP-FPM probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/index.php/PHP_VALUE%0Asession.auto_start=1",
        "/index.php/%0A",
        "/index.php/.php",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code != 404 && code != 400 {
            append_out(ctx, &format!("{}{} [{}]",
                if found == 0 { "CVE-2019-11043: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CVE-2019-11043: no matching paths");
    }
    0
}
