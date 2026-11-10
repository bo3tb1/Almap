/* sample_banner - read a service banner and clean control characters */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let mut s = match connect_ctx(ctx) {
        Some(s) => s,
        None => return 1,
    };
    let raw = recv_all(&mut s, 4096);
    drop(s);
    if raw.is_empty() {
        return 0;
    }
    let mut text = String::from_utf8_lossy(&raw).into_owned();
    while text.ends_with('\n') || text.ends_with('\r') {
        text.pop();
    }
    let text: String = text
        .chars()
        .map(|c| if (c as u32) < 32 { '.' } else { c })
        .collect();
    set_out(ctx, &text);
    0
}
