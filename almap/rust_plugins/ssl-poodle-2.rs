/* ssl-poodle-2 - SSLv3 CBC POODLE probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (rc, _ver, cipher) = tls_probe(ctx, 0x0300, &TLS_CBC_CIPHERS, false);
    if rc == 1 {
        set_out(ctx, &format!("VULNERABLE: SSLv3 CBC POODLE ({})", tls_cipher_name(cipher)));
    } else if rc == 0 {
        set_out(ctx, "not vulnerable: SSLv3 CBC POODLE");
    } else {
        set_out(ctx, "POODLE: no TLS handshake");
    }
    0
}
