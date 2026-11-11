/* pgsql-ssl-posture-4 - report PostgreSQL SSL negotiation posture */
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
        set_out(ctx, "pgsql-ssl-posture: not reachable");
        return 0;
    }
    set_out(ctx, &format!("PostgreSQL SSL: server {} SSL on startup", if ssl { "OFFERS" } else { "DOES NOT offer" }));
    0
}
