/* pgsql-auth-check-4 - PostgreSQL default-credential check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let words = ["admin", "password", "root", "test", "guest"];
    if !valid(ctx) {
        return 1;
    }
    for w in words.iter() {
        let (rc, _m) = pg_login(ctx, "postgres", w);
        if rc == 0 {
            set_out(ctx, &format!("pgsql-auth-check: postgres:{} ACCEPTED (verify)", w));
            return 0;
        }
    }
    set_out(ctx, "pgsql-auth-check: all 5 default passwords rejected");
    0
}
