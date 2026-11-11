/* rpc-dump-4 - ONC-RPC portmapper DUMP call * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("rpc-dump-4: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[128, 0, 0, 40, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1, 134, 160, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err() {
    set_out(ctx, "rpc-dump-4: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "rpc-dump-4: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("rpc-dump: RPC reply {} bytes (portmapper responding)", resp.len()));
0
}
