/* mysql-vuln-cve2012-2122-2 - five wrong-password auth attempts */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut found = false;
    for _ in 0..5 {
        let (mut s, _version, _salt) = match mysql_open(ctx) {
            Some(v) => v,
            None => { set_out(ctx, "MySQL CVE-2012-2122: no handshake"); return 0; }
        };
        let (rc, _msg) = mysql_login(&mut s, "root", "wrong", false);
        drop(s);
        if rc == 0 {
            set_out(ctx, "VULNERABLE: MySQL CVE-2012-2122 auth bypass");
            found = true;
            break;
        }
    }
    if !found {
        set_out(ctx, "not vulnerable: MySQL CVE-2012-2122");
    }
    0
}
