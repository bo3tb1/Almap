/* kerberos-userenum-4 - Kerberos AS-REQ user-enumeration surface probe */
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
            set_out(ctx, &format!("kerberos-userenum-4: KDC not reachable on port {}", port));
            return 0;
        }
    };
    drop(s);
    set_out(ctx, &format!("kerberos-userenum-4: KDC reachable on TCP {} (AS-REQ probing requires a realm)", port));
    0
}
