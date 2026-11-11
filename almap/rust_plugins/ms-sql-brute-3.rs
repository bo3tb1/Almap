/* ms-sql-brute-3 - five blank-password sa login attempts. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut found = false;

    if !valid(ctx) {
        return 1;
    }
    for _ in 0..5 {
        let (rc, _msg) = mssql_empty_login(ctx);
        if rc == 0 {
            set_out(ctx, "MSSQL brute: sa blank password accepted");
            found = true;
            break;
        }
        if rc < 0 {
            break;
        }
    }
    if !found {
        set_out(ctx, "MSSQL brute: sa blank password rejected in 5 attempts");
    }
    0
}
