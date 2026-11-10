/* http-vuln-cve2023-44487-5 - HTTP/2 Rapid Reset CVE-2023-44487 probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    /* "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + empty SETTINGS frame */
    let req: [u8; 33] = [
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50,
        0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d,
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00,
    ];
    if !valid(ctx) {
        return 1;
    }
    let port = unsafe { (*ctx).port };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("http-vuln-cve2023-44487-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "http-vuln-cve2023-44487-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 2048);
    drop(s);
    if buf.len() >= 9 && buf[3] == 0x04 {
        set_out(ctx, "http-vuln-cve2023-44487-5: HTTP/2 SETTINGS seen");
    } else {
        set_out(
            ctx,
            &format!(
                "http-vuln-cve2023-44487-5: no HTTP/2 SETTINGS ({} bytes)",
                buf.len()
            ),
        );
    }
    0
}
