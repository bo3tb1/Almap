/* dns-cache-snoop-2 - test for cached DNS answers */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let names = ["example.com", "www.example.com", "localhost"];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for name in names.iter() {
        let resp = match dns_udp(ctx, name, DNS_A, 0x0100, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if dns_rcode(&resp) == 0 && dns_ancount(&resp) > 0 {
            if found == 0 {
                out.push_str("DNS cache snoop: ");
            } else {
                out.push_str(", ");
            }
            out.push_str(name);
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "DNS cache snoop: no cached answers");
    } else {
        set_out(ctx, &out);
    }
    0
}
