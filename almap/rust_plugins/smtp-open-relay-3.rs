/* smtp-open-relay-3 - SMTP EHLO relay probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    const PROBE: &[u8] = b"EHLO almap\r\n";
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "SMTP relay: no connection");
            return 0;
        }
    };
    if send_all(&mut s, PROBE).is_err() {
        set_out(ctx, "SMTP relay: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "SMTP relay: no response");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    if contains_ci(&cleaned, "250") {
        let show: String = cleaned.chars().take(300).collect();
        set_out(ctx, &format!("SMTP relay: {}", show));
    } else {
        let show: String = cleaned.chars().take(100).collect();
        set_out(ctx, &format!("SMTP relay: no match ({})", show));
    }
    0
}
