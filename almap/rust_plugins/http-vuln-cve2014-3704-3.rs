/* http-vuln-cve2014-3704-3 - CVE-2014-3704 Drupal probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/CHANGELOG.txt",
        "/core/CHANGELOG.txt",
        "/user/login",
    ];
    let needles = ["Drupal", "Drupal", "Drupal"];
    let mut found = 0usize;
    for (i, p) in paths.iter().enumerate() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), needles[i]) {
            append_out(ctx, &format!("{}{} [{}]",
                if found == 0 { "CVE-2014-3704: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CVE-2014-3704: no matching paths");
    }
    0
}
