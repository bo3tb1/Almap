/* redis-vuln-cve2022-0543-5 - Redis CVE-2022-0543 version probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("redis-vuln-cve2022-0543-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[73, 78, 70, 79, 32, 115, 101, 114, 118, 101, 114, 13, 10]).is_err() {
    set_out(ctx, "redis-vuln-cve2022-0543-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "redis-vuln-cve2022-0543-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, "redis-vuln-cve2022-0543-5: INFO reply did not expose version");
0
}
