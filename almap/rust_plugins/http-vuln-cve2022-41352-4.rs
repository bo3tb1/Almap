/* http-vuln-cve2022-41352-4 - Zimbra tar path traversal probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/service/extension/backup/mboximport", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-41352-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "Zimbra") {
    set_out(ctx, &format!("VULNERABLE: /service/extension/backup/mboximport [{}] (CVE-2022-41352)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2022-41352 (/service/extension/backup/mboximport [{}])", http_status(&resp)));
}
0
}
