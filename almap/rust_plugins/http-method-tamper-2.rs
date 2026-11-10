/* http-method-tamper-2 - test whether PUT is accepted */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "PUT", "/almap-test.txt", None, "\r\n",
                                  "ALmap method test", Some("text/plain"), 4096) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && (code == 200 || code == 201 || code == 204) {
        set_out(ctx, &format!("VULNERABLE: HTTP PUT accepted (HTTP {})", code));
    } else {
        set_out(ctx, &format!("not vulnerable: HTTP PUT rejected (HTTP {})", code));
    }
    0
}
