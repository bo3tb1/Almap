/* http-vuln-cve2022-46169-5 - Cacti CVE-2022-46169 poller probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/remote_agent.php?action=polldata&local_data_ids[0]=1&host_id=1&poller_id=1", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2022-46169-5: no HTTP response"); return 0; }
};
set_out(ctx, &format!("http-vuln-cve2022-46169-5: HTTP {}, {} bytes", http_status(&resp), resp.len()));
0
}
