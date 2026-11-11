/* oracle-tns-info-3 - Oracle TNS listener information probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let port = unsafe { (*ctx).port };
    let s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "Oracle TNS info: not reachable");
            return 0;
        }
    };
    drop(s);
    set_out(ctx, &format!("Oracle TNS info: service reachable on port {}", port));
    0
}
