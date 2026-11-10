/* upnp-ssdp-4 - UPnP SSDP M-SEARCH discovery (UDP) * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = &[77, 45, 83, 69, 65, 82, 67, 72, 32, 42, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72, 79, 83, 84, 58, 32, 50, 51, 57, 46, 50, 53, 53, 46, 50, 53, 53, 46, 50, 53, 48, 58, 49, 57, 48, 48, 13, 10];
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "upnp-ssdp-4: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("upnp-ssdp: {}", &text));
0
}
