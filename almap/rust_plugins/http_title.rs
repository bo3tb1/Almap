/* http_title - extract the HTML title and Server header */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, b"GET / HTTP/1.0\r\n\r\n").is_err() {
        return 1;
    }
    let raw = recv_all(&mut s, 8192);
    drop(s);
    if raw.is_empty() {
        return 0;
    }
    let resp = String::from_utf8_lossy(&raw).into_owned();
    let server = http_header(&resp, "Server").unwrap_or_default();
    let lower = resp.to_ascii_lowercase();
    let mut title = String::new();
    let mut have_title = false;
    if let Some(open) = lower.find("<title>") {
        let start = open + 7;
        if let Some(rel) = lower[start..].find("</title>") {
            let raw_title = &resp[start..start + rel];
            title = raw_title
                .chars()
                .map(|c| if (c as u32) < 32 { '.' } else { c })
                .collect();
            title = title.trim().to_string();
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
