/* ssh2-enum-algos - enumerate SSH KEXINIT algorithm name-lists. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let names = [
        "kex", "hostkey", "enc-c2s", "enc-s2c", "mac-c2s", "mac-s2c", "comp-c2s", "comp-s2c",
        "lang-c2s", "lang-s2c",
    ];

    if !valid(ctx) {
        return 1;
    }
    let (mut stream, banner) = match ssh_open(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "SSH algorithms: no SSH banner");
            return 0;
        }
    };
    let kex = match ssh_get_kexinit(&mut stream, 4096) {
        Some(k) if !k.is_empty() => k,
        _ => {
            drop(stream);
            set_out(ctx, &format!("SSH algorithms: KEXINIT failed ({})", banner));
            return 0;
        }
    };
    drop(stream);
    let mut out = String::new();
    let mut lines = 0usize;
    for (i, name) in names.iter().enumerate() {
        if let Some(val) = ssh_kex_field(&kex, i, 2048) {
            if !val.is_empty() {
                if lines > 0 {
                    out.push('\n');
                }
                out.push_str(&format!("{}: {}", name, val));
                lines += 1;
            }
        }
    }
    if lines == 0 {
        set_out(ctx, "SSH algorithms: none disclosed");
    } else {
        set_out(ctx, &out);
    }
    0
}
