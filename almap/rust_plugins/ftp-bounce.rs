/* ftp-bounce - FTP PORT command bounce exposure check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let (mut stream, _banner) = match ftp_open(ctx) {
        Some(v) => v,
        None => {
            set_out(ctx, "FTP bounce: no FTP banner");
            return 0;
        }
    };
    let _ = ftp_login(
        &mut stream,
        "anonymous",
        "anonymous@example.com",
        1024,
    );
    let (code, _) = ftp_cmd(&mut stream, "PORT 127,0,0,1,0,80", 1024);
    drop(stream);
    if code == 200 {
        set_out(ctx, "VULNERABLE: FTP bounce (PORT to third party accepted)");
    } else {
        set_out(
            ctx,
            &format!("not vulnerable: FTP bounce PORT rejected (code {})", code),
        );
    }
    0
}
