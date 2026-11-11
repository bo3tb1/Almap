/* http-vuln-cve2024-38856-4 - Apache OFBiz auth bypass probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/webtools/control/ProgramExport", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-38856-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "OFBiz") {
        set_out(ctx, &format!("VULNERABLE: /webtools/control/ProgramExport [{}] (CVE-2024-38856)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2024-38856 (/webtools/control/ProgramExport [{}])", code));
    }
    0
}
