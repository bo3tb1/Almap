/* http-vuln-cve2021-22986-4 - CVE-2021-22986 BIG-IP iControl probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/mgmt/shared/authn/login", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2021-22986-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "F5") {
        set_out(ctx, &format!("VULNERABLE: /mgmt/shared/authn/login [{}] (CVE-2021-22986)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2021-22986 (/mgmt/shared/authn/login [{}])", code));
    }
    0
}
