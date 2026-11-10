/* http-vuln-cve2023-25690-3 - Apache mod_proxy smuggling probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = http_request(
        ctx,
        "POST",
        "/",
        None,
        "Transfer-Encoding: chunked\r\n",
        "0\r\n\r\n",
        Some("application/x-www-form-urlencoded"),
        8192,
    );
    let code = resp.as_ref().map(|r| http_status(r)).unwrap_or(0);
    let got = resp.as_ref().map_or(false, |r| !r.is_empty());
    if got && (code == 200 || code == 400 || code == 411) {
        set_out(
            ctx,
            &format!(
                "potentially vulnerable: CVE-2023-25690 mod_proxy smuggling (HTTP {})",
                code
            ),
        );
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2023-25690 (HTTP {})", code));
    }
    0
}
