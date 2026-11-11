/* pgsql-version-3 - PostgreSQL SSLRequest version probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const REQ: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "PostgreSQL version: no connection");
            return 0;
        }
    };
    let ok = send_all(&mut s, &REQ).is_ok();
    let r = if ok { recv_exact(&mut s, 1) } else { None };
    drop(s);
    let b0 = match r {
        Some(v) => v[0],
        None => {
            set_out(ctx, "PostgreSQL version: no SSLRequest response");
            return 0;
        }
    };
    if b0 == b'S' {
        set_out(ctx, "PostgreSQL version: SSL supported");
    } else if b0 == b'N' {
        set_out(ctx, "PostgreSQL version: SSL refused");
    } else {
        set_out(ctx, &format!("PostgreSQL version: response 0x{:02x}", b0));
    }
    0
}
