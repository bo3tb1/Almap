/* smb-vuln-ms08-067-4 - MS08-067 SMB path probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if let Some(resp) = smb2_negotiate(ctx) {
        if !resp.is_empty() {
            let dialect = smb2_dialect(&resp);
            set_out(ctx, &format!("smb-vuln-ms08-067-4: SMB2 dialect={} security=0x{:x}; verify MS08-067", smb2_dialect_name(dialect), smb2_security_mode(&resp)));
            return 0;
        }
    }
    match smb1_open_session(ctx) {
        Some((s, _uid, os, lan)) => {
            drop(s);
            set_out(ctx, &format!("smb-vuln-ms08-067-4: SMB1 os={} lan={}; verify MS08-067", os, lan));
        }
        None => {
            set_out(ctx, "smb-vuln-ms08-067-4: no SMB response; verify MS08-067");
        }
    }
    0
}
