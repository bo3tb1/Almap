/* snmp-info - SNMPv2c system group discovery */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let communities = ["public", "private"];
    let oids = ["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.3.0"];
    let labels = ["sysDescr", "sysName", "sysObjectID", "sysUpTime"];
    if !valid(ctx) {
        return 1;
    }
    let mut found = 0;
    for c in communities.iter() {
        for (i, oid) in oids.iter().enumerate() {
            if let Some(val) = snmp_get(ctx, c, oid) {
                let prefix = if found == 0 { "SNMP info: " } else { "; " };
                append_out(ctx, &format!("{}{}: {}", prefix, labels[i], val));
                found += 1;
            }
        }
        if found > 0 {
            append_out(ctx, &format!(" (community {})", c));
            break;
        }
    }
    if found == 0 {
        set_out(ctx, "SNMP info: no response with public/private");
    }
    0
}
