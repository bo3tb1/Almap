/* smb-double-pulsar-backdoor-3 - DoublePulsar exposure probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut d1: u32 = 0xFFFF;

    if !valid(ctx) {
        return 1;
    }
    if let Some(resp) = smb1_negotiate(ctx) {
        d1 = smb1_dialect(&resp);
    }
    if d1 <= 5 {
        set_out(
            ctx,
            &format!(
                "SMBv1 offered ({}); DoublePulsar not confirmed",
                smb1_dialect_name(d1)
            ),
        );
    } else {
        set_out(ctx, "SMBv1 not offered; DoublePulsar not detected");
    }
    0
}
