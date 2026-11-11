/* ssh-brute - small fixed dictionary check for root/admin */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["root", "admin"];
    let mut found = 0;
    let mut attempts = 0;
    if !valid(ctx) {
        return 1;
    }
    for u in 0..2 {
        let (mut s, _banner) = match ssh_open(ctx) {
            Some(v) => v,
            None => continue,
        };
        let kex = ssh_get_kexinit(&mut s, 2048);
        if kex.as_ref().map(|k| k.is_empty()).unwrap_or(true) {
            drop(s);
            continue;
        }
        for p in 0..10 {
            attempts += 1;
            let (rc, _m) = ssh_auth_password(&mut s, users[u], BRUTE_WORDS[p], 512);
            if rc == 1 {
                let prefix = if found == 0 { "SSH valid credentials: " } else { ", " };
                append_out(ctx, &format!("{}{}:{}", prefix, users[u], BRUTE_WORDS[p]));
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
        set_out(ctx, &format!("SSH brute: no valid credentials in 10-word dictionary ({} attempts; full auth needs completed KEX)", attempts));
    }
    0
}
