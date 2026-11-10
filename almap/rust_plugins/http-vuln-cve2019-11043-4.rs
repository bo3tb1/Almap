/* http-vuln-cve2019-11043-4 - CVE-2019-11043 PHP-FPM probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/index.php", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2019-11043-4: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "PHP") {
        set_out(ctx, &format!("VULNERABLE: /index.php [{}] (CVE-2019-11043)", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2019-11043 (/index.php [{}])", code));
    }
    0
}
