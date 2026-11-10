/* ftp-bounce-2 - FTP PORT bounce probe */
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
    let (mut code, _) = ftp_login(
        &mut stream,
        "anonymous",
        "anonymous@example.com",
        1024,
    );
    if code == 230 {
        let (c, _) = ftp_cmd(&mut stream, "PORT 127,0,0,1,0,80", 1024);
        code = c;
    }
    drop(stream);
    if code == 200 {
        set_out(ctx, "VULNERABLE: FTP PORT bounce accepted");
    } else {
        set_out(
            ctx,
            &format!("not vulnerable: FTP PORT bounce (code {})", code),
        );
    }
    0
}
