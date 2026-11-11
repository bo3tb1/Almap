/* smb-vuln-ms08-067-2 - Conficker/MS08-067 SMBv1 exposure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let neg = smb1_negotiate(ctx);
    let dialect = match &neg {
        Some(r) => smb1_dialect(r),
        None => 0xFFFF,
    };
    if neg.is_none() || dialect > 5 {
        set_out(ctx, "MS08-067: SMBv1 not offered");
        return 0;
    }
    let _ = smb1_open_session(ctx);
    set_out(ctx, &format!("potentially vulnerable: MS08-067 (SMBv1 {}; patch level not confirmed)", smb1_dialect_name(dialect)));
    0
}
