/* iot-wsdiscovery-probe-5 - WS-Discovery Probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = &[60, 101, 58, 69, 110, 118, 101, 108, 111, 112, 101, 32, 120, 109, 108, 110, 115, 58, 101, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 119, 51, 46, 111, 114, 103, 47, 50, 48, 48, 51, 47, 48, 53, 47, 115, 111, 97, 112, 45, 101, 110, 118, 101, 108, 111, 112, 101, 34, 32, 120, 109, 108, 110, 115, 58, 100, 61, 34, 104, 116, 116, 112, 58, 47, 47, 115, 99, 104, 101, 109, 97, 115, 46, 120, 109, 108, 115, 111, 97, 112, 46, 111, 114, 103, 47, 119, 115, 47, 50, 48, 48, 53, 47, 48, 52, 47, 100, 105, 115, 99, 111, 118, 101, 114, 121, 34, 62, 60, 101, 58, 66, 111, 100, 121, 62, 60, 100, 58, 80, 114, 111, 98, 101, 47, 62, 60, 47, 101, 58, 66, 111, 100, 121, 62, 60, 47, 101, 58, 69, 110, 118, 101, 108, 111, 112, 101, 62];
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "iot-wsdiscovery-probe-5: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, "iot-wsdiscovery-probe-5: not detected");
0
}
