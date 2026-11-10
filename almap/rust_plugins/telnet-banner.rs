/* telnet-banner - Telnet banner probe. */
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
            set_out(ctx, "Telnet banner: no connection");
            return 0;
        }
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(800)));
    let resp = recv_all(&mut stream, 2048);
    drop(stream);
    if resp.is_empty() {
        set_out(ctx, "Telnet banner: no banner");
        return 0;
    }
    let text = clean(&String::from_utf8_lossy(&resp));
    let short: String = text.chars().take(200).collect();
    set_out(ctx, &format!("Telnet banner: {}", short));
    0
}
