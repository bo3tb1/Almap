/* ms-sql-empty-password - test the sa account with a blank password */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (rc, msg) = mssql_empty_login(ctx);
    if rc == 0 {
        set_out(ctx, "MSSQL empty password: sa login accepted");
    } else if rc > 0 {
        set_out(ctx, &format!("MSSQL empty password: sa login rejected ({})", msg));
    } else {
        set_out(ctx, "MSSQL empty password: no TDS response");
    }
    0
}
