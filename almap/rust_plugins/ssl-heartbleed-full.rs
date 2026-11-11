/* ssl-heartbleed-full - full OpenSSL Heartbleed probe (CVE-2014-0160) */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let port = unsafe { (*ctx).port };
    let (irc, iver, icipher) = tls_probe(ctx, 0x0303, &TLS_CIPHERS, false);
    let tls_ok = irc == 1;
    let ver = tls_version_name(iver);
    let cipher = tls_cipher_name(icipher);
    let versions: [u32; 3] = [0x0303, 0x0302, 0x0301];
    let mut got_hello = false;
    for v in versions.iter() {
        let (rc, leaked) = tls_heartbleed_raw(ctx, *v);
        if rc == 1 {
            set_out(ctx, &format!(
                "VULNERABLE: OpenSSL Heartbleed (CVE-2014-0160) - server leaked {} bytes via {} HeartbeatResponse",
                leaked, tls_version_name(*v)));
            if tls_ok {
                append_out(ctx, &format!(" [handshake: {}/{}]", ver, cipher));
            }
            return 0;
        }
        if rc == 0 {
            got_hello = true;
        }
    }
    if got_hello || tls_ok {
        if tls_ok {
            set_out(ctx, &format!(
                "not vulnerable: OpenSSL Heartbleed (handshake: {}/{}; heartbeat not honored)",
                ver, cipher));
        } else {
            set_out(ctx, "not vulnerable: OpenSSL Heartbleed (TLS ServerHello seen; heartbeat not honored)");
        }
    } else {
        set_out(ctx, &format!("Heartbleed: no TLS handshake on port {}", port));
    }
    0
}
