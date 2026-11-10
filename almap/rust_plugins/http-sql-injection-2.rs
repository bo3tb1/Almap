/* http-sql-injection-2 - SQL error signature probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/?id=1%27", "/index.php?id=1%27", "/search?q=1%27"];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let body = http_body(&resp);
        if contains_ci(body, "SQL syntax")
            || contains_ci(body, "mysql_fetch")
            || contains_ci(body, "ORA-")
        {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: no SQL error signature");
    }
    0
}
