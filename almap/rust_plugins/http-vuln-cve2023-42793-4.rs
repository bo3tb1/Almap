/* http-vuln-cve2023-42793-4 - TeamCity auth bypass RCE probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let path = "/app/rest/server";
    let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2023-42793-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "TeamCity") {
        set_out(ctx, &format!("VULNERABLE: {} [{}] (CVE-2023-42793)", path, code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2023-42793 ({} [{}])", path, code));
    }
    0
}
