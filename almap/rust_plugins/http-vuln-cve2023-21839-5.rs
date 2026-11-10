/* http-vuln-cve2023-21839-5 - WebLogic CVE-2023-21839 T3 probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let req: [u8; 59] = [
        0x74, 0x33, 0x20, 0x31, 0x32, 0x2e, 0x32, 0x2e, 0x31, 0x0a, 0x41, 0x53,
        0x3a, 0x32, 0x35, 0x35, 0x0a, 0x48, 0x4c, 0x3a, 0x31, 0x39, 0x0a, 0x4d,
        0x53, 0x3a, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0a, 0x50,
        0x55, 0x3a, 0x74, 0x33, 0x3a, 0x2f, 0x2f, 0x31, 0x32, 0x37, 0x2e, 0x30,
        0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x37, 0x30, 0x30, 0x31, 0x0a, 0x0a,
    ];
    if !valid(ctx) {
        return 1;
    }
    let port = unsafe { (*ctx).port };
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, &format!("http-vuln-cve2023-21839-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, &req).is_err() {
        set_out(ctx, "http-vuln-cve2023-21839-5: send failed");
        return 0;
    }
    let buf = recv_all(&mut s, 4096);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "http-vuln-cve2023-21839-5: no response");
        return 0;
    }
    let resp = clean(&String::from_utf8_lossy(&buf));
    if contains_ci(&resp, "HELO") {
        set_out(ctx, "http-vuln-cve2023-21839-5: detected");
    } else {
        set_out(ctx, "http-vuln-cve2023-21839-5: not detected");
    }
    0
}
