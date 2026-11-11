/* iot-llmnr-query-5 - LLMNR name-resolution probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match dns_udp(ctx, "almap", 1, 0x0000, 2048) {
        Some(r) => r,
        None => {
            set_out(ctx, "iot-llmnr-query-5: no DNS reply");
            return 0;
        }
    };
    let an = dns_ancount(&resp);
    set_out(ctx, &format!("iot-llmnr-query-5: {} answer(s)", an));
    let mut answers = String::new();
    dns_dump_answers(&mut answers, &resp, 5);
    append_out(ctx, &answers);
    0
}
