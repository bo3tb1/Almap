/* NTP monlist - NTP monlist probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut probe = [0u8; 48];
    probe[0] = 23;

    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &probe, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "NTP monlist: no response");
            return 0;
        }
    };
    let text = clean(&String::from_utf8_lossy(&resp));
    let shown: String = text.chars().take(160).collect();
    set_out(
        ctx,
        &format!("NTP monlist: {} bytes: {}", resp.len(), shown),
    );
    0
}
