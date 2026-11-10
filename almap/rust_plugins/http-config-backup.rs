/* http-config-backup - look for exposed configuration backups. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let paths = ["/.env", "/.env.bak", "/config.php.bak", "/config.php~", "/wp-config.php.bak", "/wp-config.php~", "/configuration.php.bak", "/web.config.bak", "/.htaccess.bak", "/settings.py.bak", "/config.yml.bak", "/application.properties.bak"];
    let mut out = String::new();
    let mut found = 0;
    for p in paths {
        let resp = http_request(ctx, "GET", p, None, "", "", None, 8192).unwrap_or_default();
        if resp.is_empty() {
            continue;
        }
        let code = http_status(&resp);
        let body = http_body(&resp);
        if (200..300).contains(&code) && !contains_ci(body, "<html") && !contains_ci(body, "not found") && body.len() > 4 {
            out.push_str(&format!("{}{}", if found == 0 { "config backups: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "config backups: none found");
    } else {
        set_out(ctx, &out);
    }
    0
}
