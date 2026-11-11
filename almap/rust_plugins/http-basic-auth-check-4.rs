/* http-basic-auth-check-4 - HTTP Basic default-credential check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let words = ["admin", "password", "root", "test", "guest"];
    for word in words.iter() {
        let hdr = basic_auth(word, word);
        let resp = match http_request(ctx, "GET", "/", None, &hdr, "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code != 401 && code != 403 {
            set_out(ctx, &format!("http-basic-auth-check-4: {}:{} -> HTTP {} (not rejected; verify)", word, word, code));
            return 0;
        }
    }
    set_out(ctx, "http-basic-auth-check-4: all 5 default pairs rejected on /");
    0
}
