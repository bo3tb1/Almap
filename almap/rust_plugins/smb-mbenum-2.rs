/* smb-mbenum-2 - SMB2 dialect and security-mode summary. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut dialect: u32 = 0xFFFF;
    let mut mode: i32 = -1;

    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = smb2_negotiate(ctx) {
        dialect = smb2_dialect(&resp);
        mode = smb2_security_mode(&resp);
    }
    if dialect == 0xFFFF {
        set_out(ctx, "SMB mbenum: SMB2 not offered");
        return 0;
    }
    set_out(
        ctx,
        &format!(
            "SMB mbenum: {} security 0x{:02x}",
            smb2_dialect_name(dialect),
            mode
        ),
    );
    0
}
