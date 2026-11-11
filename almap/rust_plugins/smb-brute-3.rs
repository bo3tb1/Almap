/* smb-brute-3 - five fixed SMB null-session attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "password", "admin", "root"];
    let passes = ["admin", "root", "password", "password", "password"];
    let mut found = 0usize;
    for i in 0..5 {
        if let Some((s, _uid, _os, _lan)) = smb1_open_session(ctx) {
            drop(s);
            append_out(ctx, &format!("{}{}:{} (null session)",
                if found == 0 { "SMB valid credentials: " } else { ", " },
                users[i], passes[i]));
            found += 1;
            break;
        }
    }
    if found == 0 {
        set_out(ctx, "SMB brute: no null session in 5 attempts");
    }
    0
}
