/* rdp-info-3 - RDP service exposure probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("RDP info: service reachable on port {}", port)),
    None => set_out(ctx, "RDP info: not reachable"),
}
0
}
