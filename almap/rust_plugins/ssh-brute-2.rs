/* ssh-brute-2 - five fixed SSH password attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "password", "admin", "root"];
    let passes = ["admin", "root", "password", "password", "password"];
    let mut found = 0;
    if !valid(ctx) {
        return 1;
    }
    let (mut s, _banner) = match ssh_open(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "SSH brute: no SSH banner");
            return 0;
        }
    };
    let kex = ssh_get_kexinit(&mut s, 2048);
    if kex.as_ref().map(|k| k.is_empty()).unwrap_or(true) {
        drop(s);
        set_out(ctx, "SSH brute: KEXINIT failed");
        return 0;
    }
    for i in 0..5 {
        let (rc, _m) = ssh_auth_password(&mut s, users[i], passes[i], 512);
        if rc == 1 {
            let prefix = if found == 0 { "SSH valid credentials: " } else { ", " };
            append_out(ctx, &format!("{}{}:{}", prefix, users[i], passes[i]));
            found += 1;
        } else if rc < 0 {
            break;
        }
    }
    drop(s);
    if found == 0 {
        set_out(ctx, "SSH brute: no valid credentials in 5 attempts");
    }
    0
}
