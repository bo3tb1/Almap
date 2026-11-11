/* ssl-ccs-injection-2 - TLS ChangeCipherSpec injection probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (rc, ver, cipher) = tls_ccs_test(ctx);
    if rc == 1 {
        set_out(ctx, &format!("VULNERABLE: TLS CCS injection ({}, {})", tls_version_name(ver), tls_cipher_name(cipher)));
    } else if rc == 0 {
        set_out(ctx, "not vulnerable: TLS CCS injection");
    } else {
        set_out(ctx, "TLS CCS injection: no handshake");
    }
    0
}
