/* http-vuln-cve2024-27956-4 - WP Automatic SQL injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/wp-content/plugins/wp-automatic/inc/csv.php", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2024-27956-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "wp-automatic") {
        set_out(ctx, &format!("VULNERABLE: /wp-content/plugins/wp-automatic/inc/csv.php [{}] (CVE-2024-27956)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2024-27956 (/wp-content/plugins/wp-automatic/inc/csv.php [{}])", code));
    }
    0
}
