/* ldap-rootdse-4 - LDAP rootDSE reachability via anonymous bind */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    /* anonymous simple bind, LDAPv3, messageID 1 */
    let bind: [u8; 14] = [
        0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03,
        0x04, 0x00, 0x80, 0x00,
    ];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "ldap-rootdse: LDAP service not answering");
            return 0;
        }
    };
    if send_all(&mut s, &bind).is_err() {
        set_out(ctx, "ldap-rootdse: LDAP service not answering");
        return 0;
    }
    let resp = recv_all(&mut s, 256);
    drop(s);
    if resp.len() < 7 {
        set_out(ctx, "ldap-rootdse: LDAP service not answering");
        return 0;
    }
    set_out(
        ctx,
        &format!(
            "ldap-rootdse: LDAP responds ({} bytes, BindResponse 0x{:02x})",
            resp.len(),
            resp[5]
        ),
    );
    0
}
