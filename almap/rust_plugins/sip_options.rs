/* sip_options - send SIP OPTIONS (UDP, TCP fallback), extract Server header. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let ip = ip_text(ctx);
    let (target_ip, port) = unsafe { ((*ctx).target_ip, (*ctx).port) };
    let tag = target_ip.wrapping_mul(2654435761u32) ^ (port as u32);
    let req = format!(
        "OPTIONS sip:{ip} SIP/2.0\r\n\
         Via: SIP/2.0/UDP {ip}:{port};branch=z9hG4bK{tag:08x}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:almap@{ip}>;tag={tag:08x}\r\n\
         To: <sip:{ip}>\r\n\
         Call-ID: {tag:08x}@almap\r\n\
         CSeq: 1 OPTIONS\r\n\
         Contact: <sip:almap@{ip}>\r\n\
         Content-Length: 0\r\n\r\n",
        ip = ip,
        port = port,
        tag = tag
    );

    // UDP first, then TCP fallback.
    let resp = match udp_exchange(ctx, req.as_bytes(), 3072) {
        Some(r) if !r.is_empty() => r,
        _ => {
            let mut s = match connect_ctx(ctx) {
                Some(s) => s,
                None => return 1,
            };
            if send_all(&mut s, req.as_bytes()).is_err() {
                return 1;
            }
            let r = recv_all(&mut s, 3072);
            drop(s);
            if r.is_empty() {
                return 0;
            }
            r
        }
    };

    let text = String::from_utf8_lossy(&resp);
    if let Some(server) = http_header(&text, "Server") {
        set_out(ctx, &format!("Server: {}", server));
    }
    0
}
