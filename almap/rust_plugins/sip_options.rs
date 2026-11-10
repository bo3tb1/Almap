/* sip_options - * plugins/sip_options.c - NSE sip-options analog. * * Build: * gcc -shared -fPIC -o plugins/sip_options.so plugins/sip_options.c * Run: * ./ */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = "sip_options".as_bytes();
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "sip_options: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("sip_options: {}", &text[..text.len().min(220)]));
0
}
