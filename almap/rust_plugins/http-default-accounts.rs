/* http-default-accounts - HTTP Basic default credential check. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let users = ["admin", "root", "manager", "tomcat"];
    let paths = ["/", "/admin/", "/manager/html"];
    let mut out = String::new();
    let mut found = 0;
    for pth in paths {
        let probe = http_request(ctx, "GET", pth, None, "", "", None, 8192).unwrap_or_default();
        if probe.is_empty() || http_status(&probe) != 401 {
            continue;
        }
        for u in users {
            for p in 0..=10usize {
                let pass = if p == 10 { "" } else { BRUTE_WORDS[p] };
                let auth = basic_auth(u, pass);
                let resp = http_request(ctx, "GET", pth, None, &auth, "", None, 8192).unwrap_or_default();
                if !resp.is_empty() && http_status(&resp) != 401 && http_status(&resp) != 403 {
                    let disp = if pass.is_empty() { "(blank)" } else { pass };
                    out.push_str(&format!("{}{}:{} at {}", if found == 0 { "default accounts: " } else { ", " }, u, disp, pth));
                    found += 1;
                }
            }
        }
    }
    if found == 0 {
        set_out(ctx, "default accounts: no HTTP Basic defaults found");
    } else {
        set_out(ctx, &out);
    }
    0
}
