/* vnc-brute-3 - five fixed VNC password attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let passwords = ["admin", "root", "password", "123456", "vnc"];
    let mut found = 0usize;
    for pass in passwords.iter() {
        let (rc, _sectype) = vnc_try_password(ctx, pass);
        if rc == 1 {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VNC valid password: " } else { ", " }, pass));
            found += 1;
        } else if rc == 2 {
            set_out(ctx, "VNC: no authentication required");
            return 0;
        }
    }
    if found == 0 {
        set_out(ctx, "VNC brute: no valid password in 5 attempts");
    }
    0
}
