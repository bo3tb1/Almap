/* smb-check-cve2017-0144-4 - EternalBlue (MS17-010) SMBv1 exposure check. * Benign: negotiates SMBv1 and reports whether the legacy dialect answers.  */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let d1 = match smb1_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb1_dialect(&r),
        _ => 0xFFFF,
    };
    if d1 == 0xFFFF {
        set_out(ctx, "SMBv1 not answering (CVE-2017-0144 unlikely)");
        return 0;
    }
    set_out(ctx, &format!("SMBv1 negotiated: {} (CVE-2017-0144/MS17-010 surface; verify)", smb1_dialect_name(d1)));
    0
}
