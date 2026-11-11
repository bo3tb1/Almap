/* mongodb-brute-3 - five MongoDB connection attempts. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    for _ in 0..5 {
        if connect_ctx(ctx).is_some() {
            found += 1;
        }
    }
    if found > 0 {
        set_out(
            ctx,
            &format!(
                "MongoDB brute: {}/5 connections accepted; authentication required",
                found
            ),
        );
    } else {
        set_out(ctx, "MongoDB brute: no connections");
    }
    0
}
