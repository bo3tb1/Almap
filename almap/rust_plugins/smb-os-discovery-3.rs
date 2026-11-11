/* smb-os-discovery-3 - discover SMB Native OS and LAN Manager strings. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut dialect: u32 = 0xFFFF;

    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = smb1_negotiate(ctx) {
        dialect = smb1_dialect(&resp);
    }
    let (os, lan) = match smb1_open_session(ctx) {
        Some((_stream, _uid, os, lan)) => (os, lan),
        None => (String::new(), String::new()),
    };
    if os.is_empty() && lan.is_empty() && dialect == 0xFFFF {
        set_out(ctx, "SMB OS: not detected");
        return 0;
    }
    let mut out = format!(
        "SMB OS: {}",
        if os.is_empty() { "unknown" } else { os.as_str() }
    );
    if !lan.is_empty() {
        out.push_str(&format!(" LAN Manager: {}", lan));
    }
    if dialect != 0xFFFF {
        out.push_str(&format!(" dialect: {}", smb1_dialect_name(dialect)));
    }
    set_out(ctx, &out);
    0
}
