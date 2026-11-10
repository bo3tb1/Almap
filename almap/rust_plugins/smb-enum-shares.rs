/* smb-enum-shares - enumerate accessible SMB shares via Tree Connect. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let shares = [
        "IPC$", "C$", "ADMIN$", "print$", "Users", "Shared",
        "Public", "Data", "Backup", "Home",
    ];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    let server = ip_text(ctx);
    let (mut stream, uid, _os, _lan) = match smb1_open_session(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "SMB shares: SMBv1 negotiation failed");
            return 0;
        }
    };
    for share in shares.iter() {
        let service = if *share == "IPC$" { "IPC" } else { "A:" };
        let (status, _tid) = smb1_tree_connect(&mut stream, uid, &server, share, service);
        if status == 0 {
            if found == 0 {
                out.push_str("SMB shares: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(share);
            found += 1;
        }
    }
    drop(stream);
    if found == 0 {
        out.push_str("SMB shares: none accessible via null session");
    }
    set_out(ctx, &out);
    0
}
