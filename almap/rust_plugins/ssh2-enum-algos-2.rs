/* ssh2-enum-algos-2 - enumerate five SSH KEXINIT algorithm lists */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let names = ["kex", "hostkey", "enc-c2s", "enc-s2c", "mac-c2s"];
    let mut s = match ssh_open(ctx) {
        Some(v) => v,
        None => { set_out(ctx, "SSH algorithms: no SSH banner"); return 0; }
    };
    let kex = match ssh_get_kexinit(&mut s.0, 2048) {
        Some(k) => k,
        None => {
            set_out(ctx, &format!("SSH algorithms: KEXINIT failed ({})", s.1));
            return 0;
        }
    };
    drop(s);
    let mut lines = 0usize;
    for (i, name) in names.iter().enumerate() {
        if let Some(val) = ssh_kex_field(&kex, i, 1024) {
            if !val.is_empty() {
                append_out(ctx, &format!("{}{}: {}", if lines > 0 { "\n" } else { "" }, name, val));
                lines += 1;
            }
        }
    }
    if lines == 0 {
        set_out(ctx, "SSH algorithms: none disclosed");
    }
    0
}
