/* smb-check-cve2020-0796-4 - SMBGhost (SMBv3.1.1 compression) exposure check. * Benign: negotiates SMB2 and reports the top dialect offered. * Use on */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let d = match smb2_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb2_dialect(&r),
        _ => 0xFFFF,
    };
    if d == 0xFFFF {
        set_out(ctx, "SMB2 not answering (CVE-2020-0796 unlikely)");
        return 0;
    }
    set_out(ctx, &format!("SMB2 dialect {} (CVE-2020-0796 affects 3.1.1; verify compression)", smb2_dialect_name(d)));
    0
}
