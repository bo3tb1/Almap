/* smb-check-vulns-3 - combined SMBv1 vulnerability exposure check. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut d1: u32 = 0xFFFF;
    let mut d2: u32 = 0xFFFF;

    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = smb1_negotiate(ctx) {
        d1 = smb1_dialect(&resp);
    }
    if let Some(resp) = smb2_negotiate(ctx) {
        d2 = smb2_dialect(&resp);
    }
    if d1 <= 5 {
        set_out(
            ctx,
            &format!(
                "potentially vulnerable: SMBv1 offered ({}); check MS08-067 and MS17-010",
                smb1_dialect_name(d1)
            ),
        );
    } else {
        set_out(ctx, "SMBv1 not offered; MS08-067/MS17-010 not indicated");
    }
    if d2 != 0xFFFF {
        append_out(ctx, &format!("; SMB2 dialect {}", smb2_dialect_name(d2)));
    }
    0
}
