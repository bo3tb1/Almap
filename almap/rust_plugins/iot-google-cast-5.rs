/* iot-google-cast-5 - Google Cast eureka_info probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/setup/eureka_info", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "iot-google-cast-5: no HTTP response"); return 0; }
};
if contains_ci(&resp, "name") {
    set_out(ctx, &format!("iot-google-cast-5: detected (HTTP {})", http_status(&resp)));
} else {
    set_out(ctx, &format!("iot-google-cast-5: not detected (HTTP {})", http_status(&resp)));
}
0
}
