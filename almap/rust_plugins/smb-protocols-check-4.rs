/* smb-protocols-check-4 - enumerate supported SMB dialects (posture). * Use only on networks you own or have permission to scan. */
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
    append_out(ctx, &format!("SMBv1: {}", if d1 != 0xFFFF { smb1_dialect_name(d1) } else { "no" }));
    append_out(ctx, &format!(", SMB2/3: {}", if d2 != 0xFFFF { smb2_dialect_name(d2) } else { "no" }));
    0
}
