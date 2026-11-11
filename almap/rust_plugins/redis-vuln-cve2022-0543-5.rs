/* redis-vuln-cve2022-0543-5 - Redis CVE-2022-0543 version probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            let port = unsafe { (*ctx).port };
            set_out(ctx, &format!("redis-vuln-cve2022-0543-5: TCP {} not reachable", port));
            return 0;
        }
    };
    if send_all(&mut s, b"INFO server\r\n").is_err() {
        set_out(ctx, "redis-vuln-cve2022-0543-5: send failed");
        return 0;
    }
    let resp = recv_all(&mut s, 4096);
    drop(s);
    if resp.is_empty() {
        set_out(ctx, "redis-vuln-cve2022-0543-5: no INFO reply");
        return 0;
    }
    let cleaned = clean(&String::from_utf8_lossy(&resp));
    match cleaned.find("redis_version:") {
        Some(idx) => set_out(ctx, &format!("redis-vuln-cve2022-0543-5: {} (verify patch level)", &cleaned[idx..])),
        None => set_out(ctx, "redis-vuln-cve2022-0543-5: INFO reply did not expose version"),
    }
    0
}
