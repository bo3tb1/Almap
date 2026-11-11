/* http-title-2 - extract the HTML page title */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "title: no response"); return 0; }
    };
    let low = resp.to_ascii_lowercase();
    if let Some(p) = low.find("<title") {
        if let Some(gt) = resp[p..].find('>') {
            let start = p + gt + 1;
            if let Some(lt) = resp[start..].find('<') {
                set_out(ctx, &format!("title: {}", clean(&resp[start..start + lt])));
                return 0;
            }
        }
    }
    set_out(ctx, &format!("title: not found (HTTP {})", http_status(&resp)));
    0
}
