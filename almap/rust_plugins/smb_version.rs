/* smb_version - * plugins/smb_version.c - NSE smb-version analog. * * Build: * gcc -shared -fPIC -o plugins/smb_version.so plugins/smb_version.c * Run: * ./ */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("smb_version: TCP {} not reachable", port)); return 0; }
};
let buf = recv_exact(&mut s, 4).unwrap_or_default();
if buf.is_empty() {
    set_out(ctx, "smb_version: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 4 && buf[4] == 254 {
    set_out(ctx, "smb_version: expected reply seen");
} else {
    set_out(ctx, "smb_version: unexpected reply");
}
0
}
