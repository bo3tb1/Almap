/* smb-enum-users - SMB null-session user/OS reconnaissance. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let session = smb1_open_session(ctx);
    let (os, lan) = match session {
        Some((stream, _uid, os, lan)) => {
            drop(stream);
            (os, lan)
        }
        None => {
            set_out(ctx, "SMB users: SMBv1 negotiation failed");
            return 0;
        }
    };
    if os.is_empty() && lan.is_empty() {
        set_out(
            ctx,
            "SMB users: null session rejected; SAMR enumeration unavailable",
        );
    } else {
        set_out(
            ctx,
            &format!(
                "SMB users: null session accepted (OS={} LAN={}); \
                 SAMR user list requires authenticated RPC",
                if os.is_empty() { "unknown" } else { os.as_str() },
                if lan.is_empty() { "unknown" } else { lan.as_str() }
            ),
        );
    }
    0
}
