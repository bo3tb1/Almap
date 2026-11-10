/* http-default-accounts-3 - five common HTTP Basic credentials. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let users = ["admin", "root", "admin", "root", "password"];
    let passes = ["admin", "root", "password", "password", "password"];
    let mut out = String::new();
    let mut found = 0;
    for (u, pw) in users.iter().zip(passes.iter()) {
        let auth = basic_auth(u, pw);
        let resp = http_request(ctx, "GET", "/", None, &auth, "", None, 4096).unwrap_or_default();
        if !resp.is_empty() && http_status(&resp) != 401 {
            out.push_str(&format!("{}{}:{}", if found == 0 { "HTTP default accounts: " } else { ", " }, u, pw));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "HTTP default accounts: none accepted");
    } else {
        set_out(ctx, &out);
    }
    0
}
