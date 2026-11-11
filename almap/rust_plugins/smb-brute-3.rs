/* smb-brute-3 - five fixed SMB null-session attempts. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "password", "admin", "root"];
    let passes = ["admin", "root", "password", "password", "password"];
    let mut found = false;

    if !valid(ctx) {
        return 1;
    }
    for i in 0..5 {
        if let Some((stream, _uid, _os, _lan)) = smb1_open_session(ctx) {
            drop(stream);
            append_out(
                ctx,
                &format!("SMB valid credentials: {}:{} (null session)", users[i], passes[i]),
            );
            found = true;
            break;
        }
    }
    if !found {
        set_out(ctx, "SMB brute: no null session in 5 attempts");
    }
    0
}
