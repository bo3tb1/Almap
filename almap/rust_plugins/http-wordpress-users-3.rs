/* http-wordpress-users-3 - probe WordPress user disclosure endpoints. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/wp-json/wp/v2/users", "/?author=1", "/author/admin/"];
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if http_status(&resp) < 400
            && (contains_ci(&resp, "\"slug\"")
                || contains_ci(&resp, "author")
                || contains_ci(&resp, "admin"))
        {
            let prefix = if found == 0 { "WordPress users: " } else { ", " };
            append_out(ctx, &format!("{}{}", prefix, path));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "WordPress users: no disclosure");
    }
    0
}
