/* jboss-console-auth-check-4 - JBoss jmx-console default-credential check
 * Tries a fixed 5-entry test dictionary of common defaults via HTTP Basic
 * auth against /jmx-console/. Use only on networks you own or have permission to scan.
 */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let words = ["admin", "password", "root", "test", "guest"];

    if !valid(ctx) {
        return 1;
    }
    for w in words.iter() {
        let hdr = basic_auth(w, w);
        let resp = match http_request(ctx, "GET", "/jmx-console/", None, &hdr, "", None, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        if code != 401 && code != 403 {
            set_out(
                ctx,
                &format!(
                    "jboss-console-auth-check-4: {}:{} -> HTTP {} (not rejected; verify)",
                    w, w, code
                ),
            );
            return 0;
        }
    }
    set_out(
        ctx,
        "jboss-console-auth-check-4: all 5 default pairs rejected on /jmx-console/",
    );
    0
}
