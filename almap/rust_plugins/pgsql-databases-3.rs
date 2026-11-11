/* pgsql-databases-3 - PostgreSQL database enumeration probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("PostgreSQL databases: service reachable on port {}", port)),
    None => set_out(ctx, "PostgreSQL databases: not reachable"),
}
0
}
