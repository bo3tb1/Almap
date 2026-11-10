/* oracle-listener-3 - Oracle listener exposure probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("Oracle listener: service reachable on port {}", port)),
    None => set_out(ctx, "Oracle listener: not reachable"),
}
0
}
