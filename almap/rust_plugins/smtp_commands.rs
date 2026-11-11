/* smtp_commands - * plugins/smtp_commands.c - NSE smtp-commands analog. * * Build: * gcc -shared -fPIC -o plugins/smtp_commands.so plugins/smtp_commands.c * R */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("smtp_commands: TCP {} not reachable", port)); return 0; }
};
let buf0 = recv_all(&mut s, 4096);
if send_all(&mut s, &[69, 72, 76, 79, 32, 97, 108, 109, 97, 112, 46, 108, 111, 99, 97, 108, 13, 10]).is_err() {
    set_out(ctx, "smtp_commands: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "smtp_commands: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("smtp_commands: {}", &resp.chars().take(220).collect::<String>()));
0
}
