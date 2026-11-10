/* smb-mbenum-3 - SMB2 dialect and security-mode summary. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (dialect, mode) = match smb2_negotiate(ctx) {
        Some(r) if !r.is_empty() => (smb2_dialect(&r), smb2_security_mode(&r)),
        _ => (0xFFFF, -1),
    };
    if dialect == 0xFFFF {
        set_out(ctx, "SMB mbenum: SMB2 not offered");
        return 0;
    }
    set_out(ctx, &format!("SMB mbenum: {} security 0x{:02x}", smb2_dialect_name(dialect), mode));
    0
}
