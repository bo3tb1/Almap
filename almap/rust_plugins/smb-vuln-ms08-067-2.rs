/* smb-vuln-ms08-067-2 - Conficker/MS08-067 SMBv1 exposure check. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let d1 = match smb1_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb1_dialect(&r),
        _ => 0xFFFF,
    };
    if d1 == 0xFFFF || d1 > 5 {
        set_out(ctx, "MS08-067: SMBv1 not offered");
        return 0;
    }
    if let Some((s, _uid, _os, _lan)) = smb1_open_session(ctx) {
        drop(s);
    }
    set_out(ctx, &format!("potentially vulnerable: MS08-067 (SMBv1 {}; patch level not confirmed)", smb1_dialect_name(d1)));
    0
}
