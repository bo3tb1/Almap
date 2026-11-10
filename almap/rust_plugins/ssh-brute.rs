/* ssh-brute - small fixed dictionary check for root/admin */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["root", "admin"];
    let words = ["admin", "root", "password", "123456", "toor", "letmein",
                 "qwerty", "test", "guest", "default"];
    let mut found = 0usize;
    let mut attempts = 0usize;
    for user in users.iter() {
        let (mut s, _banner) = match ssh_open(ctx) {
            Some(v) => v,
            None => continue,
        };
        if ssh_get_kexinit(&mut s, 2048).is_none() {
            drop(s);
            continue;
        }
        for pass in words.iter() {
            attempts += 1;
            let (rc, _methods) = ssh_auth_password(&mut s, user, pass, 512);
            if rc == 1 {
                append_out(ctx, &format!("{}{}:{}",
                    if found == 0 { "SSH valid credentials: " } else { ", " },
                    user, pass));
                found += 1;
                break;
            }
            if rc < 0 {
                break;
            }
        }
        drop(s);
    }
    if found == 0 {
        set_out(ctx, &format!(
            "SSH brute: no valid credentials in 10-word dictionary ({} attempts; full auth needs completed KEX)",
            attempts));
    }
    0
}
