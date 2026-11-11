/* svc-iscsi-5 - iSCSI target reachability probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("svc-iscsi-5: service reachable on TCP {}", port)),
    None => set_out(ctx, &format!("svc-iscsi-5: TCP {} not reachable", port)),
}
0
}
