/* mysql-empty-password - test MySQL/MariaDB accounts with blank passwords. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let users = ["root", "mysql", "admin", "test"];
    let mut found = 0;

    if !valid(ctx) {
        return 1;
    }
    for user in users.iter() {
        let (mut s, version) = match mysql_open(ctx) {
            Some(v) => v,
            None => {
                set_out(ctx, "MySQL empty password: no MySQL handshake");
                return 0;
            }
        };
        let rc = mysql_login(&mut s, user, "", true);
        drop(s);
        if rc == 0 {
            let prefix = if found == 0 {
                "MySQL empty password: "
            } else {
                ", "
            };
            append_out(ctx, &format!("{}{}@{}", prefix, user, version));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "MySQL empty password: none accepted");
    }
    0
}
