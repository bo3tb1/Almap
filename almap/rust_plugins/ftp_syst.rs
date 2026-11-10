/* ftp-syst - read the FTP greeting, send SYST, extract the 215 reply. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    let (code, _greeting) = ftp_reply(&mut stream, 1024);
    if code != 220 {
        return 0;
    }
    let (code2, reply) = ftp_cmd(&mut stream, "SYST", 768);
    drop(stream);
    if code2 != 215 {
        return 0;
    }
    let mut syst = String::new();
    for raw in reply.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        let lb = line.as_bytes();
        if lb.len() >= 3 && &lb[..3] == b"215" {
            let mut text = &lb[3..];
            if !text.is_empty() && (text[0] == b' ' || text[0] == b'-') {
                text = &text[1..];
            }
            syst = String::from_utf8_lossy(text).into_owned();
            if lb.get(3) == Some(&b' ') {
                break;
            }
        }
    }
    syst = clean(&syst);
    if !syst.is_empty() {
        set_out(ctx, &format!("SYST: {}", syst));
    }
    0
}
