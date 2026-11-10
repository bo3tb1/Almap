/* ftp-vsftpd-backdoor - vsftpd 2.3.4 smiley backdoor probe. */
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
            set_out(ctx, "vsftpd backdoor: no FTP banner");
            return 0;
        }
    };
    let (mut code, _) = ftp_cmd(&mut stream, "USER anonymous:)", 1024);
    if code == 331 {
        let (c, _) = ftp_cmd(&mut stream, "PASS almap@example.com", 1024);
        code = c;
    }
    drop(stream);
    if contains_ci(&banner, "vsftpd 2.3.4") && (code == 230 || code == 530) {
        set_out(
            ctx,
            &format!("VULNERABLE: vsftpd 2.3.4 smiley backdoor ({})", banner),
        );
    } else {
        set_out(
            ctx,
            &format!(
                "not vulnerable: vsftpd backdoor not confirmed (code {})",
                code
            ),
        );
    }
    0
}
