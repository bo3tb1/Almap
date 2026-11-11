/* smb-vuln-ms17-010-full - * smb-vuln-ms17-010-full - full MS17-010 "EternalBlue" detection. * * Unlike the lightweight variants (which only confir */
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
        set_out(ctx, &format!("smb-vuln-ms17-010-full: SMBv1 not offered (SMB2 dialect {}); MS17-010 not applicable", smb2_dialect_name(d2)));
        return 0;
    }
    let (mut s, uid, os, _lan) = match smb1_open_session(ctx) {
        Some(v) => v,
        None => { set_out(ctx, &format!("smb-vuln-ms17-010-full: SMBv1 {} offered but session setup failed; cannot confirm MS17-010", smb1_dialect_name(d1))); return 0; },
    };
    let ip = ip_text(ctx);
    let (treestatus, tid) = smb1_tree_connect(&mut s, uid, &ip, "IPC$", "?????");
    if treestatus != 0 {
        drop(s);
        set_out(ctx, &format!("smb-vuln-ms17-010-full: SMBv1 {}; IPC$ tree connect denied (status 0x{:08X}); likely patched or hardened", smb1_dialect_name(d1), treestatus as u32));
        if !os.is_empty() {
            append_out(ctx, &format!(" OS={}", os));
        }
        return 0;
    }
    let status = smb1_ms17_peek(&mut s, tid, uid);
    drop(s);
    if status == 0xC0000205 {
        set_out(ctx, "VULNERABLE: MS17-010 EternalBlue (CVE-2017-0143) - PeekNamedPipe returned STATUS_INSUFF_SERVER_RESOURCES");
    } else if status == 0xC0000022 || status == 0xC0000008 {
        set_out(ctx, &format!("not vulnerable: MS17-010 (PeekNamedPipe status 0x{:08X}; patched)", status));
    } else if status == 0xFFFFFFFF {
        set_out(ctx, &format!("potentially vulnerable: MS17-010 (SMBv1 {}, IPC$ reachable; no PeekNamedPipe reply - verify manually)", smb1_dialect_name(d1)));
    } else {
        set_out(ctx, &format!("MS17-010 inconclusive: SMBv1 {}, PeekNamedPipe status 0x{:08X}", smb1_dialect_name(d1), status));
    }
    if !os.is_empty() {
        append_out(ctx, &format!(" OS={}", os));
    }
    0
}
