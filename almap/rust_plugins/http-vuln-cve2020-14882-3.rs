/* http-vuln-cve2020-14882-3 - CVE-2020-14882 Oracle WebLogic */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/console/login/LoginForm.jsp",
        "/console/",
        "/wls-wsat/CoordinatorPortType",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if contains_ci(http_body(&resp), "WebLogic") {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: CVE-2020-14882 Oracle WebLogic");
    } else {
        append_out(ctx, " (CVE-2020-14882 Oracle WebLogic)");
    }
    0
}
