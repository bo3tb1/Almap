/*
 * smb-enum-shares (Rust) - enumerate accessible SMB shares via Tree
 * Connect. Faithful port of smb-enum-shares.c.
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");
include!("smb.rs");

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let shares = [
        "IPC$", "C$", "ADMIN$", "print$", "Users", "Shared", "Public", "Data", "Backup", "Home",
    ];
    let ip = as_ip_text(ctx.target_ip);
    let (mut s, uid, _os, _lan) = match ar_smb1_open_session(ctx) {
        Some(t) => t,
        None => {
            ar_out(ctx, "SMB shares: SMBv1 negotiation failed");
            return 0;
        }
    };
    let mut found = 0;
    for sh in shares.iter() {
        let service = if *sh == "IPC$" { "IPC" } else { "A:" };
        let (st, _tid) = ar_smb1_tree_connect(&mut s, uid, &ip, sh, service, ctx.timeout_ms);
        if st == 0 {
            ar_append(
                ctx,
                &format!("{}{}", if found == 0 { "SMB shares: " } else { ", " }, sh),
            );
            found += 1;
        }
    }
    if found == 0 {
        ar_out(ctx, "SMB shares: none accessible via null session");
    }
    0
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if ctx.is_null() {
        return 1;
    }
    let ctx: &AlScriptContext = unsafe { &*ctx };
    run(ctx)
}
