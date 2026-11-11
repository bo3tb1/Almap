/* http-vuln-cve2025-1094-5 - PostgreSQL CVE-2025-1094 SSLRequest probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("http-vuln-cve2025-1094-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[0, 0, 0, 8, 4, 210, 22, 47]).is_err() {
    set_out(ctx, "http-vuln-cve2025-1094-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "http-vuln-cve2025-1094-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("http-vuln-cve2025-1094-5: unexpected reply ({} bytes)", resp.len()));
0
}
