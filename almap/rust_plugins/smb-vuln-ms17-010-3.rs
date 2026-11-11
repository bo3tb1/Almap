/* smb-vuln-ms17-010-3 - EternalBlue SMBv1 exposure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let d2 = smb2_negotiate(ctx).map(|r| smb2_dialect(&r)).unwrap_or(0xFFFF);
    let neg1 = smb1_negotiate(ctx);
    let d1 = neg1.as_ref().map(|r| smb1_dialect(r)).unwrap_or(0xFFFF);
    if d1 > 5 {
        set_out(ctx, &format!("MS17-010: SMBv1 not offered (SMB2 dialect 0x{:04x})", d2));
        return 0;
    }
    let os = match smb1_open_session(ctx) {
        Some((s, _u, os, _l)) => {
            drop(s);
            os
        }
        None => String::new(),
    };
    let mut out = format!("potentially vulnerable: MS17-010 EternalBlue (SMBv1 {}; patch level not confirmed)", smb1_dialect_name(d1));
    if !os.is_empty() {
        out.push_str(&format!(" OS={}", os));
    }
    set_out(ctx, &out);
    0
}
