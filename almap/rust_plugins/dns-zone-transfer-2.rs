/* dns-zone-transfer-2 - attempt AXFR for three likely zones */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let zones = ["example.com", "test", "local"];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for zone in zones.iter() {
        let resp = match dns_tcp_query(ctx, zone, DNS_AXFR, 0, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if dns_rcode(&resp) == 0 && dns_ancount(&resp) > 0 {
            if found == 0 {
                out.push_str("DNS zone transfer: ");
            }
            out.push_str(&format!("{}\n", zone));
            dns_dump_answers(&mut out, &resp, 6);
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "DNS zone transfer: refused or no records");
    } else {
        set_out(ctx, &out);
    }
    0
}
