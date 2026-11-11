/* mqtt-auth-check-4 - MQTT default-credential check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let words = ["admin", "password", "root", "test", "guest"];
    for word in words.iter() {
        let wl = word.len();
        let mut pkt = vec![0u8; 64];
        let mut o = 0usize;
        pkt[o] = 0x10; o += 1;
        pkt[o] = (12 + 2 + wl + 2 + wl) as u8; o += 1;
        pkt[o] = 0x00; o += 1; pkt[o] = 0x04; o += 1;
        pkt[o..o + 4].copy_from_slice(b"MQTT"); o += 4;
        pkt[o] = 0x04; o += 1; pkt[o] = 0xc2; o += 1;
        pkt[o] = 0x00; o += 1; pkt[o] = 0x3c; o += 1;
        pkt[o] = 0x00; o += 1; pkt[o] = 0x00; o += 1;
        pkt[o] = 0x00; o += 1; pkt[o] = wl as u8; o += 1;
        pkt[o..o + wl].copy_from_slice(word.as_bytes()); o += wl;
        pkt[o] = 0x00; o += 1; pkt[o] = wl as u8; o += 1;
        pkt[o..o + wl].copy_from_slice(word.as_bytes()); o += wl;

        let mut s = match connect_ctx(ctx) {
            Some(s) => s,
            None => { set_out(ctx, "mqtt-auth-check: not reachable"); return 0; }
        };
        if send_all(&mut s, &pkt[..o]).is_err() { continue; }
        let r = recv_all(&mut s, 64);
        if r.len() >= 4 && r[0] == 0x20 && r[3] == 0 {
            set_out(ctx, &format!("mqtt-auth-check: {}:{} ACCEPTED (verify)", word, word));
            return 0;
        }
    }
    set_out(ctx, "mqtt-auth-check: all 5 default pairs rejected");
    0
}
