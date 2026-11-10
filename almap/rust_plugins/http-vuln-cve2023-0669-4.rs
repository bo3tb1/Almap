/* http-vuln-cve2023-0669-4 - GoAnywhere MFT deserialization probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/goanywhere/lic/accept", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2023-0669-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "GoAnywhere") {
    set_out(ctx, &format!("VULNERABLE: /goanywhere/lic/accept [{}] (CVE-2023-0669)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2023-0669 (/goanywhere/lic/accept [{}])", http_status(&resp)));
}
0
}
