/* ssl-heartbleed - Heartbleed CVE-2014-0160 heartbeat probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let rc = tls_heartbleed(ctx);
    if rc == 1 {
        set_out(ctx, "VULNERABLE: Heartbleed CVE-2014-0160 (heartbeat reply)");
    } else if rc == 0 {
        set_out(ctx, "not vulnerable: Heartbleed CVE-2014-0160 not confirmed");
    } else {
        set_out(ctx, "Heartbleed: TLS handshake failed");
    }
    0
}
