/* ldap-anon-bind-4 - LDAP anonymous simple-bind check * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("ldap-anon-bind-4: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[48, 12, 2, 1, 1, 96, 7, 2, 1, 3, 4, 0, 128, 0]).is_err() {
    set_out(ctx, "ldap-anon-bind-4: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "ldap-anon-bind-4: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 5 && buf[5] == 97 {
    set_out(ctx, "ldap-anon-bind: no BindResponse");
} else {
    set_out(ctx, &format!("ldap-anon-bind: resultCode={}{}", rb[(if n > 9 { 9 } else { n - 1 })], if (rb[5] == 0x61 && rb[9] == 0x00) { " (anonymous bind ALLOWED; verify)" } else { "" }));
}
0
}
