/* pgsql-schema-check-4 - PostgreSQL startup reachability probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (rc, ssl) = pg_start(ctx, "postgres", "postgres");
    if rc < 0 {
        set_out(ctx, "pgsql-schema-check-4: PostgreSQL not reachable");
        return 0;
    }
    set_out(ctx, &format!("pgsql-schema-check-4: startup ok (ssl={}, user=postgres, db=postgres)", if ssl { "offered" } else { "disabled" }));
    0
}
