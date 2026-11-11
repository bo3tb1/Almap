/* ssh-hostkey-2 - report SSH host-key algorithms */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (mut s, banner) = match ssh_open(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "SSH hostkey: no SSH banner");
            return 0;
        }
    };
    let kex = match ssh_get_kexinit(&mut s, 2048) {
        Some(k) if !k.is_empty() => k,
        _ => {
            drop(s);
            set_out(ctx, &format!("SSH hostkey: KEXINIT failed ({})", banner));
            return 0;
        }
    };
    drop(s);
    match ssh_kex_field(&kex, 1, 1024) {
        Some(val) => set_out(ctx, &format!("SSH hostkey algorithms: {}", val)),
        None => set_out(ctx, &format!("SSH hostkey: algorithms not disclosed ({})", banner)),
    }
    0
}
