/* http_options - * plugins/http_options.c - NSE http-methods analog. * * Build: * gcc -shared -fPIC -o plugins/http_options.so plugins/http_options.c * Run:  */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("http_options: TCP {} not reachable", port)); return 0; }
};
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "http_options: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("http_options: {}", &resp.chars().take(220).collect::<String>()));
0
}
