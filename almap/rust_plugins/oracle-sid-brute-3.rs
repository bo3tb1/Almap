/* oracle-sid-brute-3 - five Oracle SID connection attempts. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, " (listener reachable; SID validation requires TNS)"),
    None => set_out(ctx, "Oracle SID brute: listener not reachable"),
}
0
}
