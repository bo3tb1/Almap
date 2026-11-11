/* iot-ethernetip-listinterfaces-5 - EtherNet/IP ListInterfaces probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = &[100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "iot-ethernetip-listinterfaces-5: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("iot-ethernetip-listinterfaces-5: unexpected reply ({} bytes)", resp.len()));
0
}
