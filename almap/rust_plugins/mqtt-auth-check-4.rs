/* mqtt-auth-check-4 - MQTT default-credential check (fixed 5-entry dict) */
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
        let wl = w.len();
        let mut pkt: Vec<u8> = Vec::new();
        pkt.push(0x10);
        pkt.push((12 + 2 + wl + 2 + wl) as u8);
        pkt.extend_from_slice(&[0x00, 0x04]);
        pkt.extend_from_slice(b"MQTT");
        pkt.extend_from_slice(&[0x04, 0xc2, 0x00, 0x3c]);
        pkt.extend_from_slice(&[0x00, 0x00]);
        pkt.push(0x00);
        pkt.push(wl as u8);
        pkt.extend_from_slice(w.as_bytes());
        pkt.push(0x00);
        pkt.push(wl as u8);
        pkt.extend_from_slice(w.as_bytes());

        let mut s = match connect_ctx(ctx) {
            Some(s) => s,
            None => {
                set_out(ctx, "mqtt-auth-check: not reachable");
                return 0;
            }
        };
        if send_all(&mut s, &pkt).is_ok() {
            let resp = recv_all(&mut s, 64);
            drop(s);
            if resp.len() >= 4 && resp[0] == 0x20 && resp[3] == 0 {
                set_out(
                    ctx,
                    &format!("mqtt-auth-check: {}:{} ACCEPTED (verify)", w, w),
                );
                return 0;
            }
        } else {
            drop(s);
        }
    }
    set_out(ctx, "mqtt-auth-check: all 5 default pairs rejected");
    0
}
