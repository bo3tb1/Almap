/* http-methods - enumerate allowed methods and test TRACE */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "OPTIONS", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => String::new(),
    };
    if !resp.is_empty() {
        if let Some(allow) = http_header(&resp, "Allow") {
            set_out(ctx, &format!("Allow: {}", allow));
        }
    }
    let trace = match http_request(ctx, "TRACE", "/", None,
                                  "X-Almap-Trace: yes\r\n", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => String::new(),
    };
    let nonempty = unsafe { !(*ctx).output_buf.is_null() && *(*ctx).output_buf != 0 };
    if !trace.is_empty() && http_status(&trace) == 200 && contains_ci(&trace, "TRACE /") {
        append_out(ctx, if nonempty { "; TRACE enabled" } else { "TRACE enabled" });
    } else if !nonempty {
        set_out(ctx, "methods: OPTIONS returned no Allow header");
    }
    0
}
