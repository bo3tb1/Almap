/* smb-os-discovery-3 - discover SMB Native OS and LAN Manager strings. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let d1 = match smb1_negotiate(ctx) {
        Some(r) if !r.is_empty() => smb1_dialect(&r),
        _ => 0xFFFF,
    };
    let (os, lan) = match smb1_open_session(ctx) {
        Some((s, _uid, os, lan)) => { drop(s); (os, lan) },
        None => (String::new(), String::new()),
    };
    if os.is_empty() && lan.is_empty() && d1 == 0xFFFF {
        set_out(ctx, "SMB OS: not detected");
        return 0;
    }
    set_out(ctx, &format!("SMB OS: {}", if !os.is_empty() { os.as_str() } else { "unknown" }));
    if !lan.is_empty() {
        append_out(ctx, &format!(" LAN Manager: {}", lan));
    }
    if d1 != 0xFFFF {
        append_out(ctx, &format!(" dialect: {}", smb1_dialect_name(d1)));
    }
    0
}
