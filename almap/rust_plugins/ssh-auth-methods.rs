/* ssh-auth-methods - enumerate SSH user-auth methods. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (mut stream, banner) = match ssh_open(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "SSH auth methods: no SSH banner");
            return 0;
        }
    };
    let kex = match ssh_get_kexinit(&mut stream, 2048) {
        Some(k) if !k.is_empty() => k,
        _ => {
            drop(stream);
            set_out(ctx, &format!("SSH auth methods: KEXINIT failed ({})", banner));
            return 0;
        }
    };
    let _ = kex;
    let (rc, methods) = ssh_auth_none(&mut stream, "root", 512);
    drop(stream);
    if rc == 1 {
        set_out(ctx, "SSH auth methods: none (no authentication required)");
    } else if rc == 0 && !methods.is_empty() {
        set_out(ctx, &format!("SSH auth methods: {}", methods));
    } else {
        set_out(
            ctx,
            &format!(
                "SSH auth methods: not disclosed before key exchange ({})",
                banner
            ),
        );
    }
    0
}
