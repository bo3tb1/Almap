/* dns-brute-2 - five fixed subdomain lookups under example.com */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let names = ["www", "mail", "ftp", "admin", "test"];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for name in names.iter() {
        let fqdn = format!("{}.example.com", name);
        let resp = match dns_udp(ctx, &fqdn, DNS_A, 0x0100, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if dns_rcode(&resp) == 0 && dns_ancount(&resp) > 0 {
            if found == 0 {
                out.push_str("DNS brute: ");
            }
            out.push_str(&format!("{} ", fqdn));
            dns_dump_answers(&mut out, &resp, 2);
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "DNS brute: no names resolved under example.com");
    } else {
        set_out(ctx, &out);
    }
    0
}
