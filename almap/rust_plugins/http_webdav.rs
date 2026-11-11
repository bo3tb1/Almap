/*
 * http_webdav.rs - NSE http-webdav analog.
 *
 * Sends an OPTIONS request and checks for the DAV response header.
 * Output: "DAV: <value>" when WebDAV is advertised, otherwise
 * "WebDAV: disabled".
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }

    let ip = ip_text(ctx);
    let req = format!(
        "OPTIONS / HTTP/1.0\r\nHost: {}\r\nUser-Agent: ALmap\r\nConnection: close\r\n\r\n",
        ip
    );

    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, req.as_bytes()).is_err() {
        return 1;
    }
    let buf = recv_all(&mut s, 3072);
    drop(s);
    if buf.is_empty() {
        return 0;
    }

    let resp = String::from_utf8_lossy(&buf);
    if let Some(dav) = http_header(&resp, "DAV") {
        set_out(ctx, &format!("DAV: {}", dav));
    } else {
        set_out(ctx, "WebDAV: disabled");
    }
    0
}
