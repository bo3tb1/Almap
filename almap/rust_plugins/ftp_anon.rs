/* ftp_anon - NSE ftp-anon analog */
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
        None => return 1,
    };
    let (code, reply) = ftp_cmd(&mut stream, "USER anonymous", 1024);
    let reply = clean(&reply);
    if code == 230 {
        set_out(ctx, &reply);
        return 0;
    }
    let (code, reply) = ftp_cmd(&mut stream, "PASS anonymous", 1024);
    let reply = clean(&reply);
    if code == 230 {
        set_out(ctx, &reply);
    } else {
        set_out(ctx, &format!("Anonymous login failed: {}", reply));
    }
    0
}
