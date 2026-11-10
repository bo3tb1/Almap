/* http-put-2 - test unauthenticated PUT acceptance */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "PUT", "/almap_test.txt", None, "\r\n",
                                  "ALmap PUT test", Some("text/plain"), 4096) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && (code == 200 || code == 201 || code == 204) {
        set_out(ctx, &format!("VULNERABLE: unauthenticated PUT accepted (HTTP {})", code));
    } else {
        set_out(ctx, &format!("not vulnerable: PUT rejected (HTTP {})", code));
    }
    0
}
