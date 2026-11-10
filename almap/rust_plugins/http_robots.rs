/* http_robots - robots.txt first-five-lines dump */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/robots.txt", None, "", "", None, 3584) {
        Some(r) if !r.is_empty() => r,
        _ => return 0,
    };
    let body = http_body(&resp).trim_start_matches(|c| c == '\r' || c == '\n');
    let lines: Vec<&str> = body.lines().take(5).collect();
    if !lines.is_empty() {
        set_out(ctx, &lines.join("\n"));
    }
    0
}
