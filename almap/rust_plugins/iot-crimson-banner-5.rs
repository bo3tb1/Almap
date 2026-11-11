/* iot-crimson-banner-5 - Crimson v3 banner probe */
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
        None => {
            set_out(ctx, &format!("iot-crimson-banner-5: TCP {} not reachable", unsafe { (*ctx).port }));
            return 0;
        }
    };
    let buf = recv_all(&mut s, 2048);
    drop(s);
    if buf.is_empty() {
        set_out(ctx, "iot-crimson-banner-5: no banner");
        return 0;
    }
    let text = clean(&String::from_utf8_lossy(&buf));
    let shown: String = text.chars().take(200).collect();
    set_out(ctx, &format!("iot-crimson-banner-5: {}", shown));
    0
}
