/* ldap-auth-check-4 - LDAP default-credential check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let words = ["admin", "password", "root", "test", "guest"];
    for word in words.iter() {
        let dn = format!("cn={}", word);
        let wl = word.len();
        let dl = dn.len();
        let inner = 3 + (2 + dl) + (2 + wl);
        let mut pkt = vec![0u8; 128];
        let mut o = 0usize;
        pkt[o] = 0x30; o += 1;
        pkt[o] = (3 + 2 + inner) as u8; o += 1;
        pkt[o] = 0x02; o += 1; pkt[o] = 0x01; o += 1; pkt[o] = 0x01; o += 1;
        pkt[o] = 0x60; o += 1; pkt[o] = inner as u8; o += 1;
        pkt[o] = 0x02; o += 1; pkt[o] = 0x01; o += 1; pkt[o] = 0x03; o += 1;
        pkt[o] = 0x04; o += 1; pkt[o] = dl as u8; o += 1;
        pkt[o..o + dl].copy_from_slice(dn.as_bytes()); o += dl;
        pkt[o] = 0x80; o += 1; pkt[o] = wl as u8; o += 1;
        pkt[o..o + wl].copy_from_slice(word.as_bytes()); o += wl;

        let mut s = match connect_ctx(ctx) {
            Some(s) => s,
            None => { set_out(ctx, "ldap-auth-check: not reachable"); return 0; }
        };
        if send_all(&mut s, &pkt[..o]).is_err() { continue; }
        let r = recv_all(&mut s, 256);
        if r.len() >= 10 && r[5] == 0x61 && r[9] == 0x00 {
            set_out(ctx, &format!("ldap-auth-check: {} ACCEPTED (verify)", dn));
            return 0;
        }
    }
    set_out(ctx, "ldap-auth-check: all 5 default binds rejected");
    0
}
