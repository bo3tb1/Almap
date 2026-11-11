/* http-wordpress-users-2 - probe WordPress user disclosure endpoints. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/wp-json/wp/v2/users",
        "/?author=1",
        "/author/admin/",
    ];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && (contains_ci(&resp, "\"slug\"") || contains_ci(&resp, "author") || contains_ci(&resp, "admin")) {
            if found == 0 {
                out.push_str("WordPress users: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{}", path));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "WordPress users: no disclosure");
    } else {
        out.push_str("");
        set_out(ctx, &out);
    }
    0
}
