/* http-vuln-cve2023-34362-3 - MOVEit Transfer probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/human.aspx",
        "/moveitisapi/moveitisapi.dll",
        "/",
    ];
    let needles = [
            "MOVEit",
            "MOVEit",
            "MOVEit",
    ];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for (path, needle) in paths.iter().zip(needles.iter()) {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code < 400 && contains_ci(http_body(&resp), needle) {
            if found == 0 {
                out.push_str("CVE-2023-34362: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{} [{}]", path, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "CVE-2023-34362: no matching paths");
    } else {
        out.push_str("");
        set_out(ctx, &out);
    }
    0
}
