/* http-vuln-cve2024-3273-5 - D-Link NAS CVE-2024-3273 probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/cgi-bin/", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2024-3273-5: no HTTP response"); return 0; }
};
set_out(ctx, &format!("http-vuln-cve2024-3273-5: HTTP {}, {} bytes", http_status(&resp), resp.len()));
0
}
