/* smb-vuln-ms08-067 - Conficker/MS08-067 SMBv1 exposure check. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match smb1_negotiate(ctx) {
        Some(r) => r,
        None => {
            set_out(ctx, "MS08-067: SMB service not reachable");
            return 0;
        }
    };
    let dialect = smb1_dialect(&resp);
    if dialect > 5 {
        set_out(
            ctx,
            &format!("MS08-067: SMBv1 not offered (dialect 0x{:04x})", dialect),
        );
        return 0;
    }
    let os = match smb1_open_session(ctx) {
        Some((stream, _uid, os, _lan)) => {
            drop(stream);
            os
        }
        None => String::new(),
    };
    let mut out = format!(
        "potentially vulnerable: MS08-067 (SMBv1 {}; patch level not confirmed)",
        smb1_dialect_name(dialect)
    );
    if !os.is_empty() {
        out.push_str(&format!(" OS={}", os));
    }
    set_out(ctx, &out);
    0
}
