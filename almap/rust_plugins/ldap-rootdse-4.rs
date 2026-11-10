/* ldap-rootdse-4 - LDAP rootDSE reachability via anonymous bind * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("ldap-rootdse-4: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[48, 12, 2, 1, 1, 96, 7, 2, 1, 3, 4, 0, 128, 0]).is_err() {
    set_out(ctx, "ldap-rootdse-4: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "ldap-rootdse-4: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("ldap-rootdse: LDAP responds ({} bytes, BindResponse 0x{:02x})", resp.len(), rb[5]));
0
}
