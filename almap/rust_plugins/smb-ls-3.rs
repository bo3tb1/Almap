/* smb-ls-3 - list access to the C$ share. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (mut s, uid, _os, _lan) = match smb1_open_session(ctx) {
        Some(v) => v,
        None => { set_out(ctx, "SMB ls: session failed"); return 0; },
    };
    let ip = ip_text(ctx);
    let (status, _tid) = smb1_tree_connect(&mut s, uid, &ip, "C$", "A:");
    drop(s);
    if status == 0 {
        set_out(ctx, "SMB ls: C$ accessible via null session");
    } else {
        set_out(ctx, "SMB ls: C$ not accessible");
    }
    0
}
