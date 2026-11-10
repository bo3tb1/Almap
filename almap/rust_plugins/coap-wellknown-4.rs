/* coap-wellknown-4 - CoAP well-known resource listing */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 21] = [
        0x40, 0x01, 0x12, 0x34, 0xbb, 0x2e, 0x77, 0x65, 0x6c, 0x6c,
        0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e, 0x44, 0x63, 0x6f, 0x72,
        0x65,
    ];

    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, &REQ, 1500) {
        Some(r) if !r.is_empty() => r,
        _ => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("coap-wellknown-4: no CoAP response on UDP {}", port));
            return 0;
        }
    };
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    let show: String = cleaned
        .chars()
        .skip(4)
        .take(180)
        .collect();
    set_out(
        ctx,
        &format!(
            "coap-wellknown-4: {} bytes from /.well-known/core: {}",
            resp.len(),
            show
        ),
    );
    0
}
