/* ssl-ccs-injection - TLS CCS injection check (CVE-2014-0224) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (rc, ver, cipher, _resp) = tls_ccs_test(ctx);
    if rc < 0 {
        set_out(ctx, "CCS injection: TLS handshake failed");
    } else if rc == 1 {
        set_out(ctx, &format!("VULNERABLE: CVE-2014-0224 early CCS accepted ({}/{})",
                              tls_version_name(ver), tls_cipher_name(cipher)));
    } else {
        set_out(ctx, &format!("not vulnerable: early CCS rejected ({}/{})",
                              tls_version_name(ver), tls_cipher_name(cipher)));
    }
    0
}
