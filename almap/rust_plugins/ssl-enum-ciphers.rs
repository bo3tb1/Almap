/* ssl-enum-ciphers - enumerate negotiated TLS cipher per version */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let versions: [u32; 4] = [0x0300, 0x0301, 0x0302, 0x0303];
    let mut found = 0usize;
    for v in versions.iter() {
        let (rc, _selver, selcipher) = tls_probe(ctx, *v, &TLS_CIPHERS, false);
        if rc == 1 {
            append_out(ctx, &format!("{}{}: {}", if found == 0 { "TLS ciphers: " } else { "; " },
                                     tls_version_name(*v), tls_cipher_name(selcipher)));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "TLS ciphers: no supported handshake");
    }
    0
}
