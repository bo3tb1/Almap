/* http-vuln-cve2022-1388-3 - CVE-2022-1388 F5 iControl REST probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "POST", "/mgmt/shared/authn/login", None, "\r\n",
                                  "{\"username\":\"admin\",\"password\":\"\"}",
                                  Some("application/json"), 8192) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && (code == 200 || contains_ci(&resp, "token")) {
        set_out(ctx, &format!(
            "potentially vulnerable: CVE-2022-1388 F5 iControl REST (HTTP {})", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2022-1388 (HTTP {})", code));
    }
    0
}
