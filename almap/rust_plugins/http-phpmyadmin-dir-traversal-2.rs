/* http-phpmyadmin-dir-traversal-2 - detect phpMyAdmin setup paths */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/phpmyadmin/scripts/setup.php",
        "/phpMyAdmin/scripts/setup.php",
        "/pma/scripts/setup.php",
    ];
    let needles = ["phpMyAdmin", "phpMyAdmin", "phpMyAdmin"];
    let mut found = 0usize;
    for (i, p) in paths.iter().enumerate() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), needles[i]) {
            append_out(ctx, &format!("{}{} [{}]",
                if found == 0 { "phpMyAdmin: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "phpMyAdmin: no matching paths");
    }
    0
}
