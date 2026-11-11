/* vnc-brute - small fixed dictionary check for VNC authentication. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut found = 0;
    let mut noauth = false;

    if !valid(ctx) {
        return 1;
    }
    for i in 0..10 {
        let rc = vnc_try_password(ctx, BRUTE_WORDS[i]);
        if rc == 2 {
            noauth = true;
            break;
        }
        if rc == 1 {
            let prefix = if found == 0 {
                "VNC valid password: "
            } else {
                ", "
            };
            append_out(ctx, &format!("{}{}", prefix, BRUTE_WORDS[i]));
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
