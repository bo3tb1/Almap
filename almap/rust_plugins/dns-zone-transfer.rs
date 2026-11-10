/* dns-zone-transfer - attempt AXFR for likely zones */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

fn axfr_try(ctx: *mut AlScriptContext, zone: &str, out: &mut String) -> i32 {
    let query = match dns_make_query(zone, DNS_AXFR, 0x0000) {
        Some(q) => q,
        None => return -1,
    };
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => return -1,
    };
    if !dns_tcp_send(&mut stream, &query) {
        return -1;
    }
    let mut total = 0i32;
    let mut first = true;
    for _ in 0..8 {
        let resp = match dns_tcp_recv(&mut stream, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => break,
        };
        if dns_rcode(&resp) != 0 {
            break;
        }
        if first {
            out.push_str(&format!("DNS zone transfer: {}\n", zone));
            first = false;
        }
        total += dns_dump_answers(out, &resp, 12) as i32;
    }
    total
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut out = String::new();
    if !valid(ctx) {
        return 1;
    }

    let ip = ip_text(ctx);
    let mut labels: Vec<&str> = ip.split('.').collect();
    labels.reverse();
    let reverse = format!("{}.in-addr.arpa", labels.join("."));
    if axfr_try(ctx, &reverse, &mut out) > 0 {
        set_out(ctx, &out);
        return 0;
    }

    for zone in ["example.com", "test", "local"].iter() {
        if axfr_try(ctx, zone, &mut out) > 0 {
            set_out(ctx, &out);
            return 0;
        }
    }
    set_out(ctx, "DNS zone transfer: refused or no records");
    0
}
