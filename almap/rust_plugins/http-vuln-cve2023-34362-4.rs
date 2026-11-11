/* http-vuln-cve2023-34362-4 - MOVEit Transfer SQL injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/human.aspx", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2023-34362-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "MOVEit") {
    set_out(ctx, &format!("VULNERABLE: /human.aspx [{}] (CVE-2023-34362)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2023-34362 (/human.aspx [{}])", http_status(&resp)));
}
0
}
