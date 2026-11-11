/* smb-vuln-ms07-029-4 - MS07-029 SMB probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    if let Some(r) = smb2_negotiate(ctx) {
        set_out(ctx, &format!("smb-vuln-ms07-029-4: SMB2 dialect={} security=0x{:x}; verify MS07-029", smb2_dialect_name(smb2_dialect(&r)), smb2_security_mode(&r)));
        return 0;
    }
    match smb1_open_session(ctx) {
        Some((stream, _uid, os, lan)) => {
            drop(stream);
            set_out(ctx, &format!("smb-vuln-ms07-029-4: SMB1 os={} lan={}; verify MS07-029", os, lan));
        }
        None => set_out(ctx, "smb-vuln-ms07-029-4: no SMB response; verify MS07-029"),
    }
    0
}
