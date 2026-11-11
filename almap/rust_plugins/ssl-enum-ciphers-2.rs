/* ssl-enum-ciphers-2 - enumerate negotiated TLS versions and ciphers */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let versions = [0x0300u16, 0x0301, 0x0302, 0x0303];
    if !valid(ctx) {
        return 1;
    }
    let mut found = 0;
    for &v in versions.iter() {
        let (rc, _selver, selcipher) = tls_probe(ctx, v, &TLS_CIPHERS, false);
        if rc == 1 {
            let prefix = if found == 0 { "TLS ciphers: " } else { "; " };
            append_out(ctx, &format!("{}{}: {}", prefix, tls_version_name(v), tls_cipher_name(selcipher)));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "TLS ciphers: no supported handshake");
    }
    0
}
