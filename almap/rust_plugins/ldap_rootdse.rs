/* ldap_rootdse - * plugins/ldap_rootdse.c - NSE ldap-rootdse analog. * * Build: * gcc -shared -fPIC -o plugins/ldap_rootdse.so plugins/ldap_rootdse.c * Run:  */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("ldap_rootdse: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[48, 12, 2, 1, 1, 96, 7, 2, 1, 3, 4, 0, 128, 0]).is_err() {
    set_out(ctx, "ldap_rootdse: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "ldap_rootdse: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("ldap_rootdse: {}", &resp.chars().take(220).collect::<String>()));
0
}
