/* http-vuln-cve2022-40684-4 - Fortinet FortiOS auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let path = "/api/v2/cmdb/system/admin";
    let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2022-40684-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Fortinet") {
        set_out(ctx, &format!("VULNERABLE: {} [{}] (CVE-2022-40684)", path, code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2022-40684 ({} [{}])", path, code));
    }
    0
}
