/* iot-airplay-info-5 - AirPlay /info probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/info", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "iot-airplay-info-5: no HTTP response");
            return 0;
        }
    };
    let code = http_status(&resp);
    if contains_ci(&resp, "deviceID") {
        set_out(ctx, &format!("iot-airplay-info-5: detected (HTTP {})", code));
    } else {
        set_out(ctx, &format!("iot-airplay-info-5: not detected (HTTP {})", code));
    }
    0
}
