/* mongodb-brute-3 - five MongoDB connection attempts. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("mongodb-brute-3: service reachable on TCP {}", port)),
    None => set_out(ctx, "MongoDB brute: no connections"),
}
0
}
