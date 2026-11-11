/* http-vuln-cve2024-23897-3 - Jenkins CLI arbitrary file read probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/cli?remoting=false", "/cli", "/login"];
    let needles = ["Jenkins", "jenkins", "Jenkins"];
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    for (i, path) in paths.iter().enumerate() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), needles[i]) {
            let prefix = if found == 0 { "CVE-2024-23897: " } else { ", " };
            append_out(ctx, &format!("{}{} [{}]", prefix, path, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CVE-2024-23897: no matching paths");
    }
    0
}
