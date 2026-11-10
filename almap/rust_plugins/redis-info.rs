/* redis-info - Redis INFO command probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;
use std::time::Duration;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    if !valid(ctx) {
        return 1;
    }
    let mut stream = match connect_ctx(ctx) {
        Some(s) => s,
        None => {
            set_out(ctx, "Redis info: no connection");
            return 0;
        }
    };
    if send_all(&mut stream, b"INFO\r\n").is_err() {
        set_out(ctx, "Redis info: send failed");
        return 0;
    }
    let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
    let resp = recv_all(&mut stream, 4096);
    drop(stream);
    if resp.is_empty() {
        set_out(ctx, "Redis info: no response");
        return 0;
    }
    let text = clean(&String::from_utf8_lossy(&resp));
    if contains_ci(&text, "redis_version") {
        let short: String = text.chars().take(300).collect();
        set_out(ctx, &format!("Redis info: {}", short));
    } else {
        let short: String = text.chars().take(100).collect();
        set_out(ctx, &format!("Redis info: no match ({})", short));
    }
    0
}
