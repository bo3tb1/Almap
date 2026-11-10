/* smb-enum-users-2 - test null-session user enumeration. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (os, ok) = match smb1_open_session(ctx) {
        Some((s, _uid, os, _lan)) => { drop(s); (os, true) },
        None => (String::new(), false),
    };
    let _ = &os;
    if ok {
        set_out(ctx, "SMB users: null session accepted; user list not exposed by this probe");
    } else {
        set_out(ctx, "SMB users: null session denied");
    }
    0
}
