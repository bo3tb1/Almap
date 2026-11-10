/* ftp-proftpd-backdoor - ProFTPD 1.3.3c ACIDBITCHEZ probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (mut stream, banner) = match ftp_open(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "ProFTPD backdoor: no FTP banner");
            return 0;
        }
    };
    let (code, reply) = ftp_cmd(&mut stream, "HELP ACIDBITCHEZ", 1024);
    drop(stream);
    if contains_ci(&banner, "ProFTPD 1.3.3c")
        || contains_ci(&reply, "ACIDBITCHEZ")
        || contains_ci(&reply, "220")
    {
        set_out(
            ctx,
            &format!("VULNERABLE: ProFTPD 1.3.3c backdoor ({})", banner),
        );
    } else {
        set_out(
            ctx,
            &format!(
                "not vulnerable: ProFTPD backdoor not confirmed (code {})",
                code
            ),
        );
    }
    0
}
