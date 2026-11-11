/* ssh-auth-methods-2 - enumerate SSH user-auth methods */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut s = match ssh_open(ctx) {
        Some(v) => v,
        None => { set_out(ctx, "SSH auth methods: no SSH banner"); return 0; }
    };
    let banner = s.1.clone();
    if ssh_get_kexinit(&mut s.0, 2048).is_none() {
        set_out(ctx, &format!("SSH auth methods: KEXINIT failed ({})", banner));
        return 0;
    }
    let (rc, methods) = ssh_auth_none(&mut s.0, "root", 512);
    drop(s);
    if rc == 1 {
        set_out(ctx, "SSH auth methods: none (no authentication required)");
    } else if rc == 0 && !methods.is_empty() {
        set_out(ctx, &format!("SSH auth methods: {}", methods));
    } else {
        set_out(ctx, &format!("SSH auth methods: not disclosed ({})", banner));
    }
    0
}
