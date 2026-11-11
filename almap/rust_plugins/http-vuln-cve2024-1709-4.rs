/* http-vuln-cve2024-1709-4 - ConnectWise ScreenConnect auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/SetupWizard.aspx", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2024-1709-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "ScreenConnect") {
    set_out(ctx, &format!("VULNERABLE: /SetupWizard.aspx [{}] (CVE-2024-1709)", http_status(&resp)));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2024-1709 (/SetupWizard.aspx [{}])", http_status(&resp)));
}
0
}
