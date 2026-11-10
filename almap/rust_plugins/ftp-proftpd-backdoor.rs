/*
 * ftp-proftpd-backdoor (Rust) - ProFTPD 1.3.3c ACIDBITCHEZ probe.
 * Faithful port of ftp-proftpd-backdoor.c.
 * Use only on networks you own or have permission to scan.
 */
#![allow(dead_code, non_snake_case, non_upper_case_globals)]

include!("alscript.rs");

fn run(ctx: &AlScriptContext) -> i32 {
    if !ar_valid(ctx) {
        return 1;
    }
    let (mut s, banner) = match ar_ftp_open(ctx, 1024) {
        Some(t) => t,
        None => {
            ar_out(ctx, "ProFTPD backdoor: no FTP banner");
            return 0;
        }
    };
    let (code, reply) = ar_ftp_cmd(&mut s, "HELP ACIDBITCHEZ", 1024, ctx.timeout_ms);
    if ar_contains_ci(&banner, "ProFTPD 1.3.3c")
        || ar_contains_ci(&reply, "ACIDBITCHEZ")
        || ar_contains_ci(&reply, "220")
    {
        ar_out(ctx, &format!("VULNERABLE: ProFTPD 1.3.3c backdoor ({})", banner.trim()));
    } else {
        ar_out(
            ctx,
            &format!("not vulnerable: ProFTPD backdoor not confirmed (code {})", code),
        );
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
