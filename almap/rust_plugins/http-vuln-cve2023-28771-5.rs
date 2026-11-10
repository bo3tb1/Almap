/* http-vuln-cve2023-28771-5 - Zyxel CVE-2023-28771 IKE probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let req = [0u8; 20];
    match udp_exchange(ctx, &req, 2048) {
        Some(buf) => set_out(
            ctx,
            &format!(
                "http-vuln-cve2023-28771-5: expected reply seen ({} bytes)",
                buf.len()
            ),
        ),
        None => set_out(ctx, "http-vuln-cve2023-28771-5: no UDP reply"),
    }
    0
}
