/* ssh_hostkey - * plugins/ssh_hostkey.c - NSE ssh-hostkey analog. * * Build: * gcc -shared -fPIC -o plugins/ssh_hostkey.so plugins/ssh_hostkey.c * Run: * ./ */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("ssh_hostkey: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[83, 83, 72, 45, 50, 46, 48, 45, 65, 76, 109, 97, 112, 95, 49, 46, 48, 13, 10]).is_err() {
    set_out(ctx, "ssh_hostkey: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "ssh_hostkey: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("ssh_hostkey: {}", &resp.chars().take(220).collect::<String>()));
0
}
