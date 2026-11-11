/* telnet_banner - * plugins/telnet_banner.c - NSE telnet-banner analog. * * Build: * gcc -shared -fPIC -o plugins/telnet_banner.so plugins/telnet_banner.c * R */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("telnet_banner: TCP {} not reachable", port)); return 0; }
};
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "telnet_banner: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("telnet_banner: {}", &resp.chars().take(220).collect::<String>()));
0
}
