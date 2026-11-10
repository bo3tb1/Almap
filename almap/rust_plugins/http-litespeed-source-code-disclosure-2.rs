/* http-litespeed-source-code-disclosure-2 - probe LiteSpeed source backups */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/index.php.bak", "/index.php~", "/.index.php.swp"];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code != 404 && code != 400 {
            append_out(ctx, &format!("{}{} [{}]",
                if found == 0 { "LiteSpeed backups: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "LiteSpeed backups: no matching paths");
    }
    0
}
