/* iot-bacnet-readprop-5 - BACnet/IP ReadProperty probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = &[129, 10, 0, 16, 1, 4, 0, 5, 1, 12, 2, 0, 0, 0, 25, 85];
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "iot-bacnet-readprop-5: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("iot-bacnet-readprop-5: unexpected reply ({} bytes)", resp.len()));
0
}
