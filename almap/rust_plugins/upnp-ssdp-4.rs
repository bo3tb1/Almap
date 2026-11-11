/* upnp-ssdp-4 - UPnP SSDP M-SEARCH discovery (UDP) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    if !valid(ctx) {
        return 1;
    }
    let resp = match udp_exchange(ctx, MSEARCH, 2048) {
        Some(r) if !r.is_empty() => r,
        _ => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("upnp-ssdp: no SSDP reply on UDP {}", port));
            return 0;
        }
    };
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    let show: String = cleaned.chars().take(220).collect();
    set_out(ctx, &format!("upnp-ssdp: {}", show));
    0
}
