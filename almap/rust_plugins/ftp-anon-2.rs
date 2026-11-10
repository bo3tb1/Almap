/* ftp-anon-2 - anonymous FTP login check */
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
            set_out(ctx, "FTP anon: no FTP banner");
            return 0;
        }
    };
    let (mut code, _) = ftp_login(
        &mut stream,
        "anonymous",
        "anonymous@example.com",
        1024,
    );
    if code != 230 {
        let (code2, _) = ftp_login(&mut stream, "anonymous", "anonymous", 1024);
        code = code2;
    }
    drop(stream);
    if code == 230 {
        set_out(
            ctx,
            &format!("FTP anonymous login: allowed ({})", banner),
        );
    } else {
        set_out(
            ctx,
            &format!("FTP anonymous login: denied (code {})", code),
        );
    }
    0
}
