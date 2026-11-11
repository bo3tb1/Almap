/* pgsql-brute-3 - five PostgreSQL connection attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut found = 0;
    for _ in 0..5 {
        if let Some(s) = connect_ctx(ctx) {
            drop(s);
            found += 1;
        }
    }
    if found > 0 {
        set_out(ctx, &format!("PostgreSQL brute: {}/5 connections accepted; password authentication required", found));
    } else {
        set_out(ctx, "PostgreSQL brute: no connections");
    }
    0
}
