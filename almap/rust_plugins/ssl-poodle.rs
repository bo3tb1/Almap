/* ssl-poodle - SSLv3 CBC POODLE exposure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (rc, selver, selcipher) = tls_probe(ctx, 0x0300, &TLS_CBC_CIPHERS, false);
    if rc == 1 && selver == 0x0300 && tls_is_cbc(selcipher) {
        set_out(ctx, &format!("VULNERABLE: POODLE (SSLv3 CBC {})", tls_cipher_name(selcipher)));
    } else if rc == 1 {
        set_out(ctx, &format!("not vulnerable: POODLE (selected {}/{})", tls_version_name(selver), tls_cipher_name(selcipher)));
    } else {
        set_out(ctx, "not vulnerable: SSLv3 not negotiated");
    }
    0
}
