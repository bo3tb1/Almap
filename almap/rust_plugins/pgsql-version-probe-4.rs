/* pgsql-version-probe-4 - PostgreSQL startup reachability probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (rc, _s) = pg_start(ctx, "postgres", "template1");
    if rc < 0 {
        set_out(ctx, "pgsql-version-probe-4: PostgreSQL not reachable");
        return 0;
    }
    set_out(ctx, "pgsql-version-probe-4: startup ok (ssl=disabled, user=postgres, db=template1)");
    0
}
