/* http-vuln-cve2023-34362-3 - MOVEit Transfer probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/human.aspx", "/moveitisapi/moveitisapi.dll", "/"];
    if !valid(ctx) {
        return 1;
    }
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), "MOVEit") {
            append_out(
                ctx,
                &format!(
                    "{}{} [{}]",
                    if found == 0 { "CVE-2023-34362: " } else { ", " },
                    p,
                    code
                ),
            );
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CVE-2023-34362: no matching paths");
    }
    0
}
