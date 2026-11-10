/* ftp-proftpd-backdoor-2 - ProFTPD ACIDBITCHEZ probe */
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
    let (code, _) = ftp_cmd(&mut stream, "HELP ACIDBITCHEZ", 1024);
    drop(stream);
    if contains_ci(&banner, "ProFTPD") && code == 220 {
        set_out(
            ctx,
            &format!("VULNERABLE: ProFTPD backdoor (banner {})", banner),
        );
    } else {
        set_out(
            ctx,
            &format!("not vulnerable: ProFTPD backdoor (code {})", code),
        );
    }
    0
}
