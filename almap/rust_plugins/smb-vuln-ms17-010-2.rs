/* smb-vuln-ms17-010-2 - EternalBlue SMBv1 exposure check. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let d2 = match smb2_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb2_dialect(&r),
        _ => 0xFFFF,
    };
    let d1 = match smb1_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb1_dialect(&r),
        _ => 0xFFFF,
    };
    if d1 > 5 {
        set_out(ctx, &format!("MS17-010: SMBv1 not offered (SMB2 dialect 0x{:04x})", d2));
        return 0;
    }
    let mut os = String::new();
    if let Some((s, _uid, o, _lan)) = smb1_open_session(ctx) {
        drop(s);
        os = o;
    }
    set_out(ctx, &format!("potentially vulnerable: MS17-010 EternalBlue (SMBv1 {}; patch level not confirmed)", smb1_dialect_name(d1)));
    if !os.is_empty() {
        append_out(ctx, &format!(" OS={}", os));
    }
    0
}
