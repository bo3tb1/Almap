/* ssh-brute-2 - five fixed SSH password attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["admin", "root", "password", "admin", "root"];
    let passes = ["admin", "root", "password", "password", "password"];
    let (mut s, banner) = match ssh_open(ctx) {
        Some(v) => v,
        None => { set_out(ctx, "SSH brute: no SSH banner"); return 0; }
    };
    if ssh_get_kexinit(&mut s, 2048).is_none() {
        drop(s);
        set_out(ctx, "SSH brute: KEXINIT failed");
        return 0;
    }
    let mut found = 0usize;
    for i in 0..5 {
        let (rc, _methods) = ssh_auth_password(&mut s, users[i], passes[i], 512);
        if rc == 1 {
            append_out(ctx, &format!("{}{}:{}",
                if found == 0 { "SSH valid credentials: " } else { ", " },
                users[i], passes[i]));
            found += 1;
        } else if rc < 0 {
            break;
        }
    }
    drop(s);
    if found == 0 {
        set_out(ctx, &format!("SSH brute: no valid credentials in 5 attempts ({})", banner));
    }
    0
}
