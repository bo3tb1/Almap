/* redis-brute-3 - five fixed Redis AUTH attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let passes = ["admin", "root", "password", "123456", "redis"];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "Redis brute: no connection");
            return 0;
        }
    };
    let mut found = 0;
    for p in passes.iter() {
        if send_all(&mut s, format!("AUTH {}\r\n", p).as_bytes()).is_err() {
            break;
        }
        let resp = recv_line(&mut s, 256);
        if resp.is_empty() {
            break;
        }
        if resp.contains("+OK") {
            let prefix = if found == 0 { "Redis valid password: " } else { ", " };
            append_out(ctx, &format!("{}{}", prefix, p));
            found += 1;
            break;
        }
    }
    drop(s);
    if found == 0 {
        set_out(ctx, "Redis brute: no valid password in 5 attempts");
    }
    0
}
