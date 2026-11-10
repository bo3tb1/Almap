/* http-vuln-cve2022-23131-5 - CVE-2022-23131 Zabbix probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/index.php", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "http-vuln-cve2022-23131-5: no HTTP response"); return 0; },
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Zabbix") {
        set_out(ctx, &format!("http-vuln-cve2022-23131-5: detected (HTTP {})", code));
    } else {
        set_out(ctx, &format!("http-vuln-cve2022-23131-5: not detected (HTTP {})", code));
    }
    0
}
