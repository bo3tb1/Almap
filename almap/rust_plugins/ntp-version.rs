/* ntp-version - send an NTP v4 client request and read version/stratum. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut req = [0u8; 48];
    req[0] = 0x23; /* LI=0, version=4, mode=3 (client) */
    let resp = match udp_exchange(ctx, &req, 512) {
        Some(r) => r,
        None => return 0,
    };
    if resp.len() < 2 {
        return 0;
    }
    let version = (resp[0] >> 3) & 7;
    let stratum = resp[1];
    set_out(
        ctx,
        &format!("NTP version:{} stratum:{}", version, stratum),
    );
    0
}
