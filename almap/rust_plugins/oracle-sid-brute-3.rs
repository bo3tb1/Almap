/* oracle-sid-brute-3 - five Oracle SID connection attempts. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let sids = ["XE", "ORCL", "ORCLCDB", "TEST", "DEV"];
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    for sid in sids.iter() {
        if connect_ctx(ctx).is_some() {
            let prefix = if found == 0 {
                "Oracle SID candidates: "
            } else {
                ", "
            };
            append_out(ctx, &format!("{}{}", prefix, sid));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "Oracle SID brute: listener not reachable");
    } else {
        append_out(ctx, " (listener reachable; SID validation requires TNS)");
    }
    0
}
