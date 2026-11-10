/* http-stored-xss-2 - stored XSS reflection probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let payload = "<script>alert(1)</script>";
    let resp = match http_request(ctx, "POST", "/", None, "\r\n", payload,
                                  Some("text/plain"), 8192) {
        Some(r) => r,
        _ => String::new(),
    };
    if !resp.is_empty() && http_body(&resp).contains(payload) {
        set_out(ctx, "potentially vulnerable: stored XSS payload reflected");
    } else {
        set_out(ctx, &format!("not vulnerable: XSS payload not reflected (HTTP {})",
                              http_status(&resp)));
    }
    0
}
