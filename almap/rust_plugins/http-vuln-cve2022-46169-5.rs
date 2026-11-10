/* http-vuln-cve2022-46169-5 - Cacti CVE-2022-46169 poller probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(
        ctx,
        "GET",
        "/remote_agent.php?action=polldata&local_data_ids[0]=1&host_id=1&poller_id=1",
        None,
        "",
        "",
        None,
        4096,
    ) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "http-vuln-cve2022-46169-5: no HTTP response");
            return 0;
        }
    };
    set_out(
        ctx,
        &format!(
            "http-vuln-cve2022-46169-5: HTTP {}, {} bytes",
            http_status(&resp),
            resp.len()
        ),
    );
    0
}
