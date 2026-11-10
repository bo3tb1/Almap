/* http-title-3 - extract the HTML page title */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "title: no response"); return 0; }
    };
    let lower = resp.to_ascii_lowercase();
    if let Some(open) = lower.find("<title") {
        if let Some(gt) = resp[open..].find('>') {
            let start = open + gt + 1;
            if let Some(lt) = resp[start..].find('<') {
                let mut title: String = resp[start..start + lt].chars().take(255).collect();
                title = clean(&title);
                set_out(ctx, &format!("title: {}", title));
                return 0;
            }
        }
    }
    set_out(ctx, &format!("title: not found (HTTP {})", http_status(&resp)));
    0
}
