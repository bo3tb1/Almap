/* pgsql-users-3 - PostgreSQL user enumeration probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("PostgreSQL users: service reachable on port {}", port)),
    None => set_out(ctx, "PostgreSQL users: not reachable"),
}
0
}
