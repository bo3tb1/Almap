/* pgsql-ssl-posture-4 - report PostgreSQL SSL negotiation posture */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (rc, _s) = pg_start(ctx, "postgres", "postgres");
    if rc == -2 {
        set_out(ctx, "PostgreSQL SSL: server OFFERS SSL on startup");
        return 0;
    }
    if rc < 0 {
        set_out(ctx, "pgsql-ssl-posture: not reachable");
        return 0;
    }
    set_out(ctx, "PostgreSQL SSL: server DOES NOT offer SSL on startup");
    0
}
