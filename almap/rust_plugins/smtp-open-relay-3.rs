/* smtp-open-relay-3 - SMTP EHLO relay probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, "SMTP relay: no connection"); return 0; }
};
if send_all(&mut s, &[69, 72, 76, 79, 32, 97, 108, 109, 97, 112, 13, 10]).is_err() {
    set_out(ctx, "SMTP relay: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "SMTP relay: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "250") {
    set_out(ctx, &format!("SMTP relay: no match ({})", &resp));
} else {
    set_out(ctx, &format!("SMTP relay: {}", &resp));
}
0
}
