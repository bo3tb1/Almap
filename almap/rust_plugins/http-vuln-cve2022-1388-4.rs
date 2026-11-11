/* http-vuln-cve2022-1388-4 - F5 BIG-IP iControl auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/mgmt/tm/util/bash", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-1388-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "F5") {
    set_out(ctx, &format!("VULNERABLE: /mgmt/tm/util/bash [{}] (CVE-2022-1388)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2022-1388 (/mgmt/tm/util/bash [{}])", http_status(&resp)));
}
0
}
