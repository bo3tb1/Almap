/* pop3-brute-3 - five fixed POP3 USER/PASS attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "password", "admin", "root"];
    let passes = ["admin", "root", "password", "password", "password"];
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => { set_out(ctx, "POP3 brute: no connection"); return 0; }
    };
    let mut found = 0usize;
    for i in 0..5 {
        let cmd = format!("USER {}\r\n", users[i]);
        if send_all(&mut s, cmd.as_bytes()).is_err() {
            break;
        }
        if recv_line(&mut s, 512).is_empty() {
            break;
        }
        let cmd = format!("PASS {}\r\n", passes[i]);
        if send_all(&mut s, cmd.as_bytes()).is_err() {
            break;
        }
        let resp = recv_line(&mut s, 512);
        if resp.is_empty() {
            break;
        }
        if resp.contains("+OK") {
            append_out(ctx, &format!("{}{}:{}",
                if found == 0 { "POP3 valid credentials: " } else { ", " },
                users[i], passes[i]));
            found += 1;
            break;
        }
    }
    drop(s);
    if found == 0 {
        set_out(ctx, "POP3 brute: no valid credentials in 5 attempts");
    }
    0
}
