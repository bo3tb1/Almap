/* svc-tftp-5 - TFTP read-request probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let text: String;
let req = &[0, 1, 97, 108, 109, 97, 112, 0, 111, 99, 116, 101, 116, 0];
let resp = match udp_exchange(ctx, req, 4096) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "svc-tftp-5: no response"); return 0; }
};
text = clean(&String::from_utf8_lossy(&resp));
set_out(ctx, &format!("svc-tftp-5: unexpected reply ({} bytes)", resp.len()));
0
}
