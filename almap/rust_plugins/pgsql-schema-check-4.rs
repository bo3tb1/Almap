/* pgsql-schema-check-4 - PostgreSQL startup / role reachability probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (rc, _s) = pg_start(ctx, "postgres", "postgres");
    if rc < 0 {
        set_out(ctx, "pgsql-schema-check-4: PostgreSQL not reachable");
        return 0;
    }
    set_out(ctx, "pgsql-schema-check-4: startup ok (ssl=disabled, user=postgres, db=postgres)");
    0
}
