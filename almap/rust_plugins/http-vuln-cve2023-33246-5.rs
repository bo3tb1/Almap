/* http-vuln-cve2023-33246-5 - RocketMQ CVE-2023-33246 broker probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
match connect_ctx(ctx) {
    Some(_) => set_out(ctx, &format!("http-vuln-cve2023-33246-5: service reachable on TCP {}", port)),
    None => set_out(ctx, &format!("http-vuln-cve2023-33246-5: TCP {} not reachable", port)),
}
0
}
