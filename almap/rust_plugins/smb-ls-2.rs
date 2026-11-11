/* smb-ls-2 - list access to the C$ share. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let server = ip_text(ctx);
    let (mut stream, uid, _os, _lan) = match smb1_open_session(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "SMB ls: session failed");
            return 0;
        }
    };
    let (status, _tid) = smb1_tree_connect(&mut stream, uid, &server, "C$", "A:");
    drop(stream);
    if status == 0 {
        set_out(ctx, "SMB ls: C$ accessible via null session");
    } else {
        set_out(ctx, "SMB ls: C$ not accessible");
    }
    0
}
