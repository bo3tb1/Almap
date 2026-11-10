/* http-methods - enumerate allowed methods and test TRACE */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut out = String::new();
    if let Some(resp) = http_request(ctx, "OPTIONS", "/", None, "", "", None, 8192) {
        if let Some(allow) = http_header(&resp, "Allow") {
            out.push_str(&format!("Allow: {}", allow));
        }
    }
    let tr = http_request(ctx, "TRACE", "/", None, "X-Almap-Trace: yes\r\n", "", None, 8192)
        .unwrap_or_default();
    if !tr.is_empty() && http_status(&tr) == 200 && contains_ci(&tr, "TRACE /") {
        if !out.is_empty() { out.push_str("; "); }
        out.push_str("TRACE enabled");
    } else if out.is_empty() {
        out.push_str("methods: OPTIONS returned no Allow header");
    }
    set_out(ctx, &out);
    0
}
