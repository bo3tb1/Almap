/* vnc-brute - small fixed dictionary check for VNC authentication */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let words = ["admin", "root", "password", "123456", "vnc", "test", "guest",
                 "letmein", "secret", "default"];
    let mut found = 0usize;
    let mut noauth = false;
    for pass in words.iter() {
        let (rc, _sectype) = vnc_try_password(ctx, pass);
        if rc == 2 {
            noauth = true;
            break;
        }
        if rc == 1 {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VNC valid password: " } else { ", " }, pass));
            found += 1;
            break;
        }
    }
    if noauth {
        set_out(ctx, "VNC: no authentication required (security type None)");
    } else if found == 0 {
        set_out(ctx, "VNC brute: no valid password in 10-word dictionary");
    }
    0
}
