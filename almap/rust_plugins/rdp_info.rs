/* rdp_info - * plugins/rdp_info.c - NSE rdp-ntlm-info analog (negotiation only). * * Build: * gcc -shared -fPIC -o plugins/rdp_info.so plugins/rdp_info.c */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("rdp_info: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[3, 0, 0, 19, 14, 224, 0, 0, 0, 0, 0, 1, 0, 8, 0, 3, 0, 0, 0]).is_err() {
    set_out(ctx, "rdp_info: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "rdp_info: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 11 && buf[11] == 2 {
    set_out(ctx, "rdp_info: expected reply seen");
} else {
    set_out(ctx, "rdp_info: unexpected reply");
}
0
}
