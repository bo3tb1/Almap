/* smb-check-vulns-2 - combined SMBv1 vulnerability exposure check. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let d1 = match smb1_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb1_dialect(&r),
        _ => 0xFFFF,
    };
    let d2 = match smb2_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb2_dialect(&r),
        _ => 0xFFFF,
    };
    if d1 <= 5 {
        set_out(ctx, &format!("potentially vulnerable: SMBv1 offered ({}); check MS08-067 and MS17-010", smb1_dialect_name(d1)));
    } else {
        set_out(ctx, "SMBv1 not offered; MS08-067/MS17-010 not indicated");
    }
    if d2 != 0xFFFF {
        append_out(ctx, &format!("; SMB2 dialect {}", smb2_dialect_name(d2)));
    }
    0
}
