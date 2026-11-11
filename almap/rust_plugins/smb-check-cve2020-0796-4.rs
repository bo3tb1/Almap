/* smb-check-cve2020-0796-4 - SMBGhost (SMBv3.1.1 compression) exposure check. */
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
            set_out(ctx, "SMB2 not answering (CVE-2020-0796 unlikely)");
            return 0;
        }
    };
    set_out(
        ctx,
        &format!(
            "SMB2 dialect {} (CVE-2020-0796 affects 3.1.1; verify compression)",
            smb2_dialect_name(smb2_dialect(&resp))
        ),
    );
    0
}
