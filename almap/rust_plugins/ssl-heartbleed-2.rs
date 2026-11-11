/* ssl-heartbleed-2 - OpenSSL Heartbleed check (CVE-2014-0160) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let (rc, _resp) = tls_heartbleed(ctx);
    if rc == 1 {
        set_out(ctx, "VULNERABLE: OpenSSL Heartbleed (CVE-2014-0160)");
    } else if rc == 0 {
        set_out(ctx, "not vulnerable: OpenSSL Heartbleed");
    } else {
        set_out(ctx, "Heartbleed: no TLS handshake");
    }
    0
}
