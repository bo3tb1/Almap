/* smb-enum-domains-3 - probe SMB domain enumeration. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (stream, _uid, _os, _lan) = match smb1_open_session(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "SMB domains: null session denied");
            return 0;
        }
    };
    drop(stream);
    set_out(ctx, "SMB domains: null session accepted; full enumeration requires credentials");
    0
}
