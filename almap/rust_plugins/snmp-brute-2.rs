/* snmp-brute-2 - SNMPv2c community dictionary check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let communities = ["public", "private", "admin", "root", "password"];
    let mut found = 0usize;
    for c in communities.iter() {
        if snmp_get(ctx, c, "1.3.6.1.2.1.1.1.0").is_some() {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "SNMP communities: " } else { ", " }, c));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "SNMP communities: none accepted");
    }
    0
}
