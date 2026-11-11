/* ms-sql-databases-3 - MSSQL database enumeration probe. */
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
            set_out(ctx, "MSSQL databases: not reachable");
            return 0;
        }
    };
    drop(s);
    set_out(ctx, &format!("MSSQL databases: service reachable on port {}", port));
    0
}
