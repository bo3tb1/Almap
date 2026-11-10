/* rmi-registry-4 - Java RMI registry liveness probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("rmi-registry-4: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[74, 82, 77, 73, 0, 2, 75]).is_err() {
    set_out(ctx, "rmi-registry-4: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "rmi-registry-4: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 0 && buf[0] == 78 {
    set_out(ctx, "rmi-registry-4: no JRMP response");
} else {
    set_out(ctx, &format!("rmi-registry-4: JRMP ack=0x{:02x}{}", rb[0], if rb[0] == 0x4e { " (RMI registry live; verify)" } else { "" }));
}
0
}
