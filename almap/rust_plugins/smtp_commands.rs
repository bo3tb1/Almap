/* smtp_commands - read the SMTP greeting, send EHLO, collect extensions. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

fn append_ext(dst: &mut String, text: &str) {
    if text.is_empty() {
        return;
    }
    if !dst.is_empty() {
        dst.push_str(", ");
    }
    dst.push_str(text);
}

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };

    // Skip multiline "220-" greeting lines, up to the final "220" line.
    let mut line = recv_line(&mut s, 1024);
    let mut guard = 0;
    while !line.is_empty() && line.starts_with("220-") && guard < 8 {
        line = recv_line(&mut s, 1024);
        guard += 1;
    }
    if line.is_empty() || !line.starts_with("220") {
        return 0;
    }

    if send_all(&mut s, b"EHLO almap.local\r\n").is_err() {
        return 1;
    }

    let mut exts = String::new();
    let mut first = true;
    let mut guard = 0;
    while guard < 64 {
        guard += 1;
        let line = recv_line(&mut s, 1024);
        if line.is_empty() || !line.starts_with("250") {
            break;
        }
        let bytes = line.as_bytes();
        if bytes.len() < 4 || (bytes[3] != b'-' && bytes[3] != b' ') {
            break;
        }
        let sep = bytes[3];
        let text = clean(&line[4..]);
        if !(first && sep == b'-') && !text.is_empty() {
            append_ext(&mut exts, &text);
        }
        first = false;
        if sep == b' ' {
            break;
        }
    }
    drop(s);

    if !exts.is_empty() {
        set_out(ctx, &format!("EHLO: {}", exts));
    }
    0
}
