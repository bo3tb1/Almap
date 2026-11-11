/* http-config-backup - look for exposed configuration backups */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/.env", "/.env.bak", "/config.php.bak", "/config.php~",
        "/wp-config.php.bak", "/wp-config.php~", "/configuration.php.bak",
        "/web.config.bak", "/.htaccess.bak", "/settings.py.bak",
        "/config.yml.bak", "/application.properties.bak",
    ];
    let mut out = String::new();
    let mut found = 0usize;
    if !valid(ctx) { return 1; }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        let body = http_body(&resp);
        if code >= 200 && code < 300 && !contains_ci(body, "<html")
            && !contains_ci(body, "not found") && body.len() > 4
        {
            if found == 0 { out.push_str("config backups: "); } else { out.push_str(", "); }
            out.push_str(path);
            found += 1;
        }
    }
    if found == 0 { set_out(ctx, "config backups: none found"); } else { set_out(ctx, &out); }
    0
}
