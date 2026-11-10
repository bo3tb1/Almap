/* ntp_version - * plugins/ntp_version.c - NSE ntp-info analog. * * Build: * gcc -shared -fPIC -o plugins/ntp_version.so plugins/ntp_version.c * Run: * ./alm */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = "ntp_version".as_bytes();
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "ntp_version: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("ntp_version: {}", &text[..text.len().min(220)]));
0
}
