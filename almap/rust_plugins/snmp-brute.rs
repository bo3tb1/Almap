/* snmp-brute - SNMPv2c community dictionary */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let communities = ["public", "private", "manager", "admin", "root", "cisco", "default", "snmp", "monitor", "secret"];
    if !valid(ctx) {
        return 1;
    }
    let mut found = 0;
    for c in communities.iter() {
        if snmp_get(ctx, c, "1.3.6.1.2.1.1.1.0").is_some() {
            let prefix = if found == 0 { "SNMP communities: " } else { ", " };
            append_out(ctx, &format!("{}{}", prefix, c));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "SNMP communities: none accepted");
    }
    0
}
