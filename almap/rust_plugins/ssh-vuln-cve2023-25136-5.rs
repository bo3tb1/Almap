/* ssh-vuln-cve2023-25136-5 - OpenSSH CVE-2023-25136 banner probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("ssh-vuln-cve2023-25136-5: TCP {} not reachable", port));
            return 0;
        }
    };
    let line = recv_line(&mut s, 512);
    drop(s);
    if line.is_empty() {
        set_out(ctx, "ssh-vuln-cve2023-25136-5: no SSH banner");
        return 0;
    }
    let line = clean(&line);
    if contains_ci(&line, "OpenSSH") {
        set_out(ctx, &format!("ssh-vuln-cve2023-25136-5: banner '{}' (verify patch level)", line));
    } else {
        set_out(ctx, &format!("ssh-vuln-cve2023-25136-5: banner '{}'", line));
    }
    0
}
