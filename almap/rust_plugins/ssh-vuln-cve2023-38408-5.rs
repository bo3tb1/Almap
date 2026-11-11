/* ssh-vuln-cve2023-38408-5 - OpenSSH banner probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => { set_out(ctx, &format!("ssh-vuln-cve2023-38408-5: TCP {} not reachable", port)); return 0; }
    };
    let raw = recv_line(&mut s, 512);
    if raw.is_empty() {
        set_out(ctx, "ssh-vuln-cve2023-38408-5: no SSH banner");
        return 0;
    }
    let line = clean(&raw);
    if contains_ci(&line, "OpenSSH") {
        set_out(ctx, &format!("ssh-vuln-cve2023-38408-5: banner '{}' (verify patch level)", line));
    } else {
        set_out(ctx, &format!("ssh-vuln-cve2023-38408-5: banner '{}'", line));
    }
    0
}
