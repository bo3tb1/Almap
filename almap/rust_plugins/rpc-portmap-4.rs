/* rpc-portmap-4 - ONC-RPC portmapper call */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const CALL: [u8; 44] = [0x80, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    if !valid(ctx) {
        return 1;
    }
    let resp = match connect_ctx(ctx) {
        Some(mut s) => {
            if send_all(&mut s, &CALL).is_ok() {
                recv_all(&mut s, 1024)
            } else {
                Vec::new()
            }
        }
        None => Vec::new(),
    };
    if resp.len() < 12 {
        let port = unsafe { (*ctx).port };
        set_out(ctx, &format!("rpc-portmap: no RPC reply on port {}", port));
        return 0;
    }
    set_out(ctx, &format!("rpc-portmap: RPC reply {} bytes (portmapper responding)", resp.len()));
    0
}
