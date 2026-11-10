/* kerberos-check-4 - Kerberos KDC port reachability probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("kerberos-check-4: KDC reachable on TCP {} (AS-REQ probing requires a realm)", port)),
    None => set_out(ctx, &format!("kerberos-check-4: KDC not reachable on port {}", port)),
}
0
}
