/* ssh_version - read the SSH protocol banner */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    let line = match recv_line(&mut s, 1024) {
        l if !l.is_empty() => l,
        _ => return 0,
    };
    drop(s);
    let version: String = line
        .trim()
        .chars()
        .map(|c| if (c as u32) < 32 { '.' } else { c })
        .collect();
    if version.starts_with("SSH-") {
        set_out(ctx, &version);
    }
    0
}
