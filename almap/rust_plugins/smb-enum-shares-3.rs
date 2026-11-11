/* smb-enum-shares-3 - probe three common SMB shares. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (mut s, uid, _os, _lan) = match smb1_open_session(ctx) {
        Some(v) => v,
        None => { set_out(ctx, "SMB shares: SMBv1 negotiation failed"); return 0; },
    };
    let ip = ip_text(ctx);
    let shares = ["IPC$", "C$", "ADMIN$"];
    let mut found = 0usize;
    for share in shares.iter() {
        let service = if *share == "IPC$" { "IPC" } else { "A:" };
        let (status, _tid) = smb1_tree_connect(&mut s, uid, &ip, share, service);
        if status == 0 {
            append_out(ctx, &format!("{}{}", if found == 0 { "SMB shares: " } else { ", " }, *share));
            found += 1;
        }
    }
    drop(s);
    if found == 0 {
        set_out(ctx, "SMB shares: none accessible via null session");
    }
    0
}
