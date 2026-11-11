/* redis_info - send INFO and extract the redis_version field. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    if send_all(&mut s, b"INFO\r\n").is_err() {
        return 1;
    }
    let resp = recv_all(&mut s, 3072);
    drop(s);
    let text = String::from_utf8_lossy(&resp);
    let idx = match text.find("redis_version:") {
        Some(i) => i + "redis_version:".len(),
        None => return 0,
    };
    // Version token: up to CR/LF/space, capped at 127 chars.
    let mut version = String::new();
    for ch in text[idx..].chars() {
        if ch == '\r' || ch == '\n' || ch == ' ' || version.len() >= 127 {
            break;
        }
        version.push(ch);
    }
    let version = clean(&version);
    if !version.is_empty() {
        set_out(ctx, &format!("redis_version:{}", version));
    }
    0
}
