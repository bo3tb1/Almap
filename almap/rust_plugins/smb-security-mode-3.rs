/* smb-security-mode-3 - report SMB signing and authentication mode. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut mode = -1i32;
    let mut smb2 = false;
    if let Some(r) = smb2_negotiate(ctx) {
        if !r.is_empty() && smb2_dialect(&r) != 0xFFFF {
            mode = smb2_security_mode(&r);
            smb2 = true;
        }
    }
    if mode < 0 {
        if let Some(r) = smb1_negotiate(ctx) {
            if !r.is_empty() {
                mode = smb1_security_mode(&r);
            }
        }
    }
    if mode < 0 {
        set_out(ctx, "SMB security mode: not detected");
        return 0;
    }
    set_out(ctx, &format!("SMB security mode: 0x{:02x} ({})", mode, if (mode & 0x01) != 0 { "user-level" } else { "share-level" }));
    append_out(ctx, &format!(", {}", if (mode & 0x02) != 0 { "encrypted passwords" } else { "plaintext passwords" }));
    append_out(ctx, &format!(", signing {}", if (mode & 0x08) != 0 { "required" } else if (mode & 0x04) != 0 { "enabled" } else { "disabled" }));
    append_out(ctx, &format!(" ({})", if smb2 { "SMB2" } else { "SMB1" }));
    0
}
