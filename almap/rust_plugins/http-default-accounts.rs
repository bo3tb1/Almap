/* http-default-accounts - HTTP Basic default credential check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "manager", "tomcat"];
    let paths = ["/", "/admin/", "/manager/html"];
    let words = [
        "admin", "root", "password", "manager", "tomcat", "guest",
        "letmein", "123456", "admin123", "password123", "",
    ];
    let mut out = String::new();
    let mut found = 0usize;
    if !valid(ctx) { return 1; }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if http_status(&resp) != 401 { continue; }
        for user in users.iter() {
            for pass in words.iter() {
                let auth = basic_auth(user, pass);
                let r = match http_request(ctx, "GET", path, None, &auth, "", None, 8192) {
                    Some(r) if !r.is_empty() => r,
                    _ => continue,
                };
                let code = http_status(&r);
                if code != 401 && code != 403 {
                    if found == 0 { out.push_str("default accounts: "); } else { out.push_str(", "); }
                    out.push_str(&format!(
                        "{}:{} at {}",
                        user,
                        if pass.is_empty() { "(blank)" } else { pass },
                        path
                    ));
                    found += 1;
                }
            }
        }
    }
    if found == 0 { set_out(ctx, "default accounts: no HTTP Basic defaults found"); }
    else { set_out(ctx, &out); }
    0
}
