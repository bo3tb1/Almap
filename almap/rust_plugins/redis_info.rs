/* redis_info - * plugins/redis_info.c - NSE redis-info analog. * * Build: * gcc -shared -fPIC -o plugins/redis_info.so plugins/redis_info.c * Run: * ./alma */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("redis_info: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[73, 78, 70, 79, 13, 10]).is_err() {
    set_out(ctx, "redis_info: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "redis_info: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("redis_info: {}", &resp.chars().take(220).collect::<String>()));
0
}
