/* smb-vuln-cve2021-44142-5 - Samba CVE-2021-44142 SMB negotiate probe */
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
            set_out(ctx, "smb-vuln-cve2021-44142-5: no SMB2 negotiate reply");
            return 0;
        }
    };
    let d = smb2_dialect(&resp);
    set_out(
        ctx,
        &format!(
            "smb-vuln-cve2021-44142-5: SMB dialect 0x{:04x} ({}); verify patch level",
            d,
            smb2_dialect_name(d)
        ),
    );
    0
}
