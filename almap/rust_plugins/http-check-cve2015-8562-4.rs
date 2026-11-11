/* http-check-cve2015-8562-4 - Joomla PHP object injection via User-Agent * (CVE detection probe; benign request, verify out-of-band). * Use only on networks you own or ha */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "User-Agent: ALmap-probe\r\nX-Forwarded-For: 127.0.0.1\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-check-cve2015-8562-4: no HTTP response"); return 0; }
};
set_out(ctx, &format!("probe sent: GET / [{}] (CVE-2015-8562; verify out-of-band)", http_status(&resp)));
0
}
