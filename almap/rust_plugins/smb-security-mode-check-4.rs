/* smb-security-mode-check-4 - report SMB signing / security mode posture. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match smb2_negotiate(ctx) {
        Some(r) => r,
        None => {
            set_out(ctx, "SMB security mode: no SMB2 response");
            return 0;
        }
    };
    let mode = smb2_security_mode(&resp);
    set_out(
        ctx,
        &format!(
            "SMB2 security mode 0x{:02x} (signing {})",
            mode,
            if mode & 0x02 != 0 {
                "required"
            } else {
                "enabled/optional"
            }
        ),
    );
    0
}
