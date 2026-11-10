/* http-default-accounts-2 - try five common HTTP Basic credentials */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "admin", "root", "password"];
    let passes = ["admin", "root", "password", "password", "password"];
    let mut found = 0usize;
    for i in 0..5 {
        let auth = basic_auth(users[i], passes[i]);
        let resp = match http_request(ctx, "GET", "/", None, &auth, "", None, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if http_status(&resp) != 401 {
            append_out(ctx, &format!("{}{}:{}",
                if found == 0 { "HTTP default accounts: " } else { ", " },
                users[i], passes[i]));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "HTTP default accounts: none accepted");
    }
    0
}
