/* iot-mdns-services-5 - DNS name-resolution probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match dns_udp(ctx, "_services._dns-sd._udp.local", 12, 0x0000, 2048) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "iot-mdns-services-5: no DNS reply"); return 0; },
    };
    let an = dns_ancount(&resp);
    let mut details = String::new();
    dns_dump_answers(&mut details, &resp, 5);
    if details.is_empty() {
        set_out(ctx, &format!("iot-mdns-services-5: {} answer(s)", an));
    } else {
        set_out(ctx, &format!("iot-mdns-services-5: {} answer(s) {}", an, details));
    }
    0
}
