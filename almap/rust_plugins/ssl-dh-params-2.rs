/* ssl-dh-params-2 - TLS DH parameter strength check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (rc, bits, group_len) = tls_dh_bits(ctx);
    if rc != 0 {
        set_out(ctx, "TLS DH params: no handshake");
        return 0;
    }
    if bits <= 0 {
        set_out(ctx, "TLS DH params: no DHE parameters offered");
    } else if bits < 2048 {
        set_out(ctx, &format!("VULNERABLE: weak {}-bit DH parameters", bits));
    } else {
        set_out(ctx, &format!("TLS DH params: {}-bit ({} bytes)", bits, group_len));
    }
    0
}
