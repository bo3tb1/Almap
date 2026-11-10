/* smb-enum-groups-2 - probe SMB group enumeration. */
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
        set_out(ctx, "SMB groups: null session accepted; full enumeration requires credentials");
    } else {
        set_out(ctx, "SMB groups: null session denied");
    }
    0
}
