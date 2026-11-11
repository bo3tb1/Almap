/* http-vuln-cve2023-22527-4 - Confluence template injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/template/aui/text-inline.vm", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2023-22527-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Confluence") {
    set_out(ctx, &format!("VULNERABLE: /template/aui/text-inline.vm [{}] (CVE-2023-22527)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2023-22527 (/template/aui/text-inline.vm [{}])", http_status(&resp)));
}
0
}
