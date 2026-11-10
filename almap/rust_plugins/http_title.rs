/* http_title - extract the HTML title and Server header */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => return 0,
    };
    let server = http_header(&resp, "Server").unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    let mut title = String::new();
    let mut have_title = false;
    if let Some(open) = lower.find("<title>") {
        let start = open + 7;
        if let Some(rel) = lower[start..].find("</title>") {
            title = resp[start..start + rel].to_string();
            title = clean(&title);
            have_title = true;
        }
    }
    let have_server = !server.is_empty();
    if have_title && have_server {
        set_out(ctx, &format!("title=\"{}\" server=\"{}\"", title, server));
    } else if have_title {
        set_out(ctx, &format!("title=\"{}\"", title));
    } else if have_server {
        set_out(ctx, &format!("server=\"{}\"", server));
    }
    0
}
