/* smb-double-pulsar-backdoor-2 - DoublePulsar exposure probe. */
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
        set_out(ctx, &format!("SMBv1 offered ({}); DoublePulsar not confirmed", 0));
        return 0;
    }
    set_out(ctx, "SMBv1 not offered; DoublePulsar not detected");
    0
}
