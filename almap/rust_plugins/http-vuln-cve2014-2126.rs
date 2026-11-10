/* http-vuln-cve2014-2126 - CVE-2014-2126 Cisco ASA ASDM */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/admin/",
        "/admin/exec/",
        "/asdm/",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if contains_ci(http_body(&resp), "ASDM") {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: CVE-2014-2126 Cisco ASA ASDM");
    } else {
        append_out(ctx, " (CVE-2014-2126 Cisco ASA ASDM)");
    }
    0
}
