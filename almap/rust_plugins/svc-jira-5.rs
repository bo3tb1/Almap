/* svc-jira-5 - Jira serverInfo probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "GET", "/rest/api/2/serverInfo", None, "", "", None, 4096) {
        Some(r) if !r.is_empty() => r,
        _ => {
            set_out(ctx, "svc-jira-5: no HTTP response");
            return 0;
        }
    };
    if contains_ci(&resp, "version") {
        set_out(ctx, &format!("svc-jira-5: detected (HTTP {})", http_status(&resp)));
    } else {
        set_out(ctx, &format!("svc-jira-5: not detected (HTTP {})", http_status(&resp)));
    }
    0
}
