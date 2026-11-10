/* dns-cache-snoop - check for cached answers and open recursion */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let domains = [
        "example.com", "google.com", "cloudflare.com", "github.com",
        "microsoft.com", "amazon.com", "facebook.com", "wikipedia.org",
        "openai.com", "localhost",
    ];
    let mut out = String::new();
    let mut found = 0usize;

    if !valid(ctx) {
        return 1;
    }
    for domain in domains.iter() {
        let resp = match dns_udp(ctx, domain, DNS_A, 0x0000, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if dns_rcode(&resp) == 0 && dns_ancount(&resp) > 0 {
            if found == 0 {
                out.push_str("DNS cache: ");
            } else {
                out.push_str("; ");
            }
            out.push_str(domain);
            out.push(' ');
            dns_dump_answers(&mut out, &resp, 1);
            found += 1;
        }
    }
    let recursion = match dns_udp(ctx, "example.com", DNS_A, 0x0100, 4096) {
        Some(r) if !r.is_empty() => dns_rcode(&r) == 0 && dns_ancount(&r) > 0,
        _ => false,
    };
    let rec = if recursion { "available" } else { "not confirmed" };
    if found == 0 {
        set_out(
            ctx,
            &format!("DNS cache: no cached answers; recursion {}", rec),
        );
    } else {
        out.push_str(&format!("; recursion {}", rec));
        set_out(ctx, &out);
    }
    0
}
