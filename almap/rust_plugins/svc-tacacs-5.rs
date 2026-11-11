/* svc-tacacs-5 - TACACS+ service reachability probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-tacacs-5: TCP {} not reachable", port));
            return 0;
        }
    };
    drop(s);
    let port = unsafe { (*ctx).port };
    set_out(ctx, &format!("svc-tacacs-5: service reachable on TCP {}", port));
    0
}
