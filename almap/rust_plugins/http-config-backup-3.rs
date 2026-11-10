/* http-config-backup-3 - find exposed configuration backups. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let paths = ["/config.php.bak", "/wp-config.php.bak", "/.env"];
    let mut out = String::new();
    let mut found = 0;
    for p in paths {
        let resp = http_request(ctx, "GET", p, None, "", "", None, 8192).unwrap_or_default();
        if resp.is_empty() {
            continue;
        }
        let code = http_status(&resp);
        if code != 404 && code != 400 {
            out.push_str(&format!("{}{} [{}]", if found == 0 { "config backups: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "config backups: no matching paths");
    } else {
        set_out(ctx, &out);
    }
    0
}
