/* http-vuln-cve2020-25213-3 - CVE-2020-25213 WP File Manager probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/wp-content/plugins/wp-file-manager/readme.txt",
        "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
        "/wp-content/plugins/wp-file-manager/",
    ];
    let needles = ["File Manager", "File Manager", "File Manager"];
    let mut found = 0usize;
    for (i, p) in paths.iter().enumerate() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), needles[i]) {
            append_out(ctx, &format!("{}{} [{}]",
                if found == 0 { "CVE-2020-25213: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CVE-2020-25213: no matching paths");
    }
    0
}
