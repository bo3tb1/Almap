/* http-vuln-cve2022-22965-3 - CVE-2022-22965 Spring4Shell probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "POST", "/", None, "\r\n",
        "class.module.classLoader.resources.context.parent.pipeline.first.pattern=ALMAP",
        Some("application/x-www-form-urlencoded"), 8192) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && (code == 200 || code == 400 || code == 500) {
        set_out(ctx, &format!(
            "potentially vulnerable: CVE-2022-22965 Spring4Shell (HTTP {})", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2022-22965 (HTTP {})", code));
    }
    0
}
