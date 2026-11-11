/* pgsql-users-3 - service reachability probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "PostgreSQL users: not reachable");
            return 0;
        }
    };
    drop(s);
    let port = unsafe { (*ctx).port };
    set_out(ctx, &format!("PostgreSQL users: service reachable on port {}", port));
    0
}
