/* http-git - detect an exposed .git directory and read HEAD. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/.git/HEAD",
        "/.git/config",
        "/.git/index",
        "/.git/logs/HEAD",
        "/.git/refs/heads/master",
        "/.git/refs/heads/main",
    ];
    let mut out = String::new();
    let mut head = String::new();
    let mut found: i32 = 0;

    if !valid(ctx) {
        return 1;
    }
    for (i, path) in paths.iter().enumerate() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) => r,
            None => continue,
        };
        let code = http_status(&resp);
        let body = http_body(&resp);
        if !resp.is_empty()
            && code == 200
            && (body.contains("ref:")
                || body.contains("[core]")
                || body.contains("DIRC")
                || body.contains("commit "))
        {
            if found == 0 {
                out.push_str("git exposed: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(path);
            found += 1;
            if i == 0 {
                let b = body.as_bytes();
                let n = if b.len() < 255 { b.len() } else { 255 };
                head = clean(&String::from_utf8_lossy(&b[..n]));
            }
        }
    }
    if found > 0 && !head.is_empty() {
        out.push_str(&format!(" HEAD={}", head));
    } else if found == 0 {
        out.push_str("git exposed: no");
    }
    set_out(ctx, &out);
    0
}
