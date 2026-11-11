/* smb-null-session-check-4 - test for anonymous (null) SMB session. * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (os, ok) = match smb1_open_session(ctx) {
        Some((s, _uid, os, _lan)) => { drop(s); (os, true) },
        None => (String::new(), false),
    };
    if ok {
        set_out(ctx, &format!("SMB null session ALLOWED (os={})", os));
        return 0;
    }
    set_out(ctx, "SMB null session refused");
    0
}
