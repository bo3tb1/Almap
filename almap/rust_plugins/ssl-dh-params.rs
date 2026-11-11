/* ssl-dh-params - inspect DHE ServerKeyExchange group size */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (rc, bits, group_len) = tls_dh_bits(ctx);
    if rc != 0 {
        set_out(ctx, "DH params: TLS handshake failed");
    } else if bits == 0 {
        set_out(ctx, "DH params: server selected ECDHE or no DHE suite");
    } else if bits <= 1024 {
        set_out(ctx, &format!("VULNERABLE: weak DH group {} bits ({} bytes)", bits, group_len));
    } else {
        set_out(ctx, &format!("DH params: {}-bit group ({} bytes)", bits, group_len));
    }
    0
}
