/* smb-protocols-check-4 - enumerate supported SMB dialects (posture). */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut out = String::new();

    if !valid(ctx) {
        return 1;
    }
    match smb1_negotiate(ctx) {
        Some(resp) => out.push_str(&format!("SMBv1: {}", smb1_dialect_name(smb1_dialect(&resp)))),
        None => out.push_str("SMBv1: no"),
    }
    match smb2_negotiate(ctx) {
        Some(resp) => out.push_str(&format!(
            ", SMB2/3: {}",
            smb2_dialect_name(smb2_dialect(&resp))
        )),
        None => out.push_str(", SMB2/3: no"),
    }
    set_out(ctx, &out);
    0
}
