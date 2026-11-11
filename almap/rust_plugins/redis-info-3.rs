/* redis-info-3 - Redis INFO command probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, "Redis info: no connection"); return 0; }
};
if send_all(&mut s, &[73, 78, 70, 79, 13, 10]).is_err() {
    set_out(ctx, "Redis info: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "Redis info: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "redis_version") {
    set_out(ctx, &format!("Redis info: no match ({})", &resp));
} else {
    set_out(ctx, &format!("Redis info: {}", &resp));
}
0
}
