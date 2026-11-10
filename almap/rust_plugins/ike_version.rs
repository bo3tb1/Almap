/* ike_version - * plugins/ike_version.c - NSE ike-version analog. * * Build: * gcc -shared -fPIC -o plugins/ike_version.so plugins/ike_version.c * Run: * ./ */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = "ike_version".as_bytes();
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "ike_version: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("ike_version: {}", &text[..text.len().min(220)]));
0
}
