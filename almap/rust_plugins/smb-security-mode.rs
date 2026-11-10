/* smb-security-mode - report SMB signing and authentication mode. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut mode: i32 = -1;
    let mut smb2 = false;

    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = smb2_negotiate(ctx) {
        if !resp.is_empty() && smb2_dialect(&resp) != 0xFFFF {
            mode = smb2_security_mode(&resp);
            smb2 = true;
        }
    }
    if !smb2 {
        if let Some(resp) = smb1_negotiate(ctx) {
            if !resp.is_empty() {
                mode = smb1_security_mode(&resp);
            }
        }
    }
    if mode < 0 {
        set_out(ctx, "SMB security mode: not detected");
        return 0;
    }
    let mut out = format!(
        "SMB security mode: 0x{:02x} ({})",
        mode,
        if (mode & 0x01) != 0 {
            "user-level"
        } else {
            "share-level"
        }
    );
    out.push_str(&format!(
        ", {}",
        if (mode & 0x02) != 0 {
            "encrypted passwords"
        } else {
            "plaintext passwords"
        }
    ));
    out.push_str(&format!(
        ", signing {}",
        if (mode & 0x08) != 0 {
            "required"
        } else if (mode & 0x04) != 0 {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!(" ({})", if smb2 { "SMB2" } else { "SMB1" }));
    set_out(ctx, &out);
    0
}
