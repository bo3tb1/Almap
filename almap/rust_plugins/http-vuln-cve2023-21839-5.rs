/* http-vuln-cve2023-21839-5 - WebLogic CVE-2023-21839 T3 probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("http-vuln-cve2023-21839-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[116, 51, 32, 49, 50, 46, 50, 46, 49, 10, 65, 83, 58, 50, 53, 53, 10, 72, 76, 58, 49, 57, 10, 77, 83, 58, 49, 48, 48, 48, 48, 48, 48, 48, 10, 80, 85, 58, 116, 51, 58, 47, 47, 49, 50, 55, 46, 48, 46, 48, 46, 49, 58, 55, 48, 48, 49, 10, 10]).is_err() {
    set_out(ctx, "http-vuln-cve2023-21839-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "http-vuln-cve2023-21839-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if contains_ci(&resp, "HELO") {
    set_out(ctx, "http-vuln-cve2023-21839-5: detected");
} else {
    set_out(ctx, "http-vuln-cve2023-21839-5: not detected");
}
0
}
