/* nfs-mountd-4 - NFS mountd service reachability probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("nfs-mountd-4: service reachable on port {} (mountd surface)", port)),
    None => set_out(ctx, &format!("nfs-mountd-4: not reachable on port {}", port)),
}
0
}
