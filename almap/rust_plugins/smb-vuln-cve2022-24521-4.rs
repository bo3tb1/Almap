/* smb-vuln-cve2022-24521-4 - Windows CLFS privilege probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if let Some(resp) = smb2_negotiate(ctx) {
        if !resp.is_empty() {
            let dialect = smb2_dialect(&resp);
            set_out(ctx, &format!("smb-vuln-cve2022-24521-4: SMB2 dialect={} security=0x{:x}; verify CVE-2022-24521", smb2_dialect_name(dialect), smb2_security_mode(&resp)));
            return 0;
        }
    }
    match smb1_open_session(ctx) {
        Some((s, _uid, os, lan)) => {
            drop(s);
            set_out(ctx, &format!("smb-vuln-cve2022-24521-4: SMB1 os={} lan={}; verify CVE-2022-24521", os, lan));
        }
        None => {
            set_out(ctx, "smb-vuln-cve2022-24521-4: no SMB response; verify CVE-2022-24521");
        }
    }
    0
}
