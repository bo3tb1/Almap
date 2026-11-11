/* rmi-registry-4 - Java RMI/JRMP handshake probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const HS: [u8; 7] = [0x4a, 0x52, 0x4d, 0x49, 0x00, 0x02, 0x4b];
    if !valid(ctx) {
        return 1;
    }
    let resp = match connect_ctx(ctx) {
        Some(mut s) => {
            if send_all(&mut s, &HS).is_ok() {
                recv_all(&mut s, 256)
            } else {
                Vec::new()
            }
        }
        None => Vec::new(),
    };
    if resp.is_empty() {
        set_out(ctx, "rmi-registry-4: no JRMP response");
        return 0;
    }
    let suffix = if resp[0] == 0x4e { " (RMI registry live; verify)" } else { "" };
    set_out(ctx, &format!("rmi-registry-4: JRMP ack=0x{:02x}{}", resp[0], suffix));
    0
}
