/* http-vuln-cve2025-1094-5 - PostgreSQL CVE-2025-1094 SSLRequest probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
    if !valid(ctx) {
        return 1;
    }
    let port = unsafe { (*ctx).port };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("http-vuln-cve2025-1094-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "http-vuln-cve2025-1094-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "http-vuln-cve2025-1094-5: no response");
        return 0;
    }
    if buf[0] == b'S' || buf[0] == b'N' {
        set_out(ctx, &format!("http-vuln-cve2025-1094-5: expected reply seen ({} bytes)", buf.len()));
    } else {
        set_out(ctx, &format!("http-vuln-cve2025-1094-5: unexpected reply ({} bytes)", buf.len()));
    }
    0
}
