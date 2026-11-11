/* smb-vuln-ms06-025-4 - MS06-025 SMB negotiate probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = smb2_negotiate(ctx) {
        let dialect = smb2_dialect(&resp);
        set_out(
            ctx,
            &format!(
                "smb-vuln-ms06-025-4: SMB2 dialect={} security=0x{:x}; verify MS06-025",
                smb2_dialect_name(dialect),
                smb2_security_mode(&resp)
            ),
        );
        return 0;
    }
    match smb1_open_session(ctx) {
        Some((stream, _uid, os, lan)) => {
            drop(stream);
            set_out(
                ctx,
                &format!(
                    "smb-vuln-ms06-025-4: SMB1 os={} lan={}; verify MS06-025",
                    os, lan
                ),
            );
        }
        None => set_out(
            ctx,
            &format!("smb-vuln-ms06-025-4: no SMB response; verify MS06-025"),
        ),
    }
    0
}
