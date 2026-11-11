/* pgsql-auth-check-4 - PostgreSQL default-credential check (5-entry dict) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let words = ["admin", "password", "root", "test", "guest"];
    for word in words.iter() {
        let (rc, _msg) = pg_login(ctx, "postgres", word);
        if rc == 0 {
            set_out(ctx, &format!("pgsql-auth-check: postgres:{} ACCEPTED (verify)", word));
            return 0;
        }
    }
    set_out(ctx, "pgsql-auth-check: all 5 default passwords rejected");
    0
}
