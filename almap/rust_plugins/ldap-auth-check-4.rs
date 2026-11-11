/* ldap-auth-check-4 - LDAP default-credential check (fixed 5-entry dict) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let words = ["admin", "password", "root", "test", "guest"];

    if !valid(ctx) {
        return 1;
    }
    for w in words.iter() {
        let dn = format!("cn={}", w);
        let wl = w.len();
        let dl = dn.len();
        let inner = 3 + (2 + dl) + (2 + wl);
        let mut pkt: Vec<u8> = Vec::new();
        pkt.push(0x30);
        pkt.push((3 + 2 + inner) as u8);
        pkt.extend_from_slice(&[0x02, 0x01, 0x01]);
        pkt.push(0x60);
        pkt.push(inner as u8);
        pkt.extend_from_slice(&[0x02, 0x01, 0x03]);
        pkt.push(0x04);
        pkt.push(dl as u8);
        pkt.extend_from_slice(dn.as_bytes());
        pkt.push(0x80);
        pkt.push(wl as u8);
        pkt.extend_from_slice(w.as_bytes());

        let mut s = match connect_ctx(ctx) {
            Some(s) => s,
            None => {
                set_out(ctx, "ldap-auth-check: not reachable");
                return 0;
            }
        };
        if send_all(&mut s, &pkt).is_ok() {
            let resp = recv_all(&mut s, 256);
            drop(s);
            if resp.len() >= 10 && resp[5] == 0x61 && resp[9] == 0x00 {
                set_out(ctx, &format!("ldap-auth-check: {} ACCEPTED (verify)", dn));
                return 0;
            }
        } else {
            drop(s);
        }
    }
    set_out(ctx, "ldap-auth-check: all 5 default binds rejected");
    0
}
