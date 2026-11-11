/* http-iis-short-name-brute-2 - probe IIS 8.3 short-name paths. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/a~1.htm",
        "/index~1.htm",
        "/default~1.asp",
    ];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code != 404 && code != 400 {
            if found == 0 {
                out.push_str("IIS short names: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{} [{}]", path, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "IIS short names: no matching paths");
    } else {
        out.push_str("");
        set_out(ctx, &out);
    }
    0
}
