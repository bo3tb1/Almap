/* svc-teamviewer-5 - TeamViewer service banner probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("svc-teamviewer-5: TCP {} not reachable", port));
            return 0;
        }
    };
    let resp = recv_all(&mut s, 2048);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "svc-teamviewer-5: no banner");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    let show: String = cleaned.chars().take(200).collect();
    set_out(ctx, &format!("svc-teamviewer-5: {}", show));
    0
}
