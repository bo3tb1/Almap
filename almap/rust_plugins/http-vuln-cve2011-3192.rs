/* http-vuln-cve2011-3192 - Apache Range header denial-of-service probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut range = String::from("Range: bytes=");
    for i in 0..100 {
        if i > 0 { range.push(','); }
        range.push_str("0-1");
    }
    range.push_str("\r\n");
    let resp = match http_request(ctx, "GET", "/", None, &range, "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "CVE-2011-3192: no response"); return 0; }
    };
    if http_status(&resp) == 206
        && (http_header(&resp, "Content-Range").is_some()
            || contains_ci(&resp, "multipart/byteranges"))
    {
        set_out(ctx, "VULNERABLE: Apache Range header DoS CVE-2011-3192 (HTTP 206)");
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2011-3192 (HTTP {})", http_status(&resp)));
    }
    0
}
