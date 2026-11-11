/* nfs-check-4 - NFS service (TCP 2049) reachability probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let port = unsafe { (*ctx).port };
    let s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("nfs-check-4: not reachable on port {}", port));
            return 0;
        }
    };
    drop(s);
    set_out(ctx, &format!("nfs-check-4: service reachable on port {} (2049 surface)", port));
    0
}
