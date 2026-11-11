/* smb-null-session-check-4 - test for anonymous (null) SMB session. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    match smb1_open_session(ctx) {
        Some((stream, _uid, os, _lan)) => {
            drop(stream);
            set_out(ctx, &format!("SMB null session ALLOWED (os={})", os));
        }
        None => set_out(ctx, "SMB null session refused"),
    }
    0
}
