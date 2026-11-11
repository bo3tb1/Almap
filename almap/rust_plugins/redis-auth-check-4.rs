/* redis-auth-check-4 - Redis AUTH default-credential / no-auth check */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let words = ["admin", "password", "root", "test", "guest"];
    if !valid(ctx) {
        return 1;
    }
    for w in words.iter() {
        let mut s = match connect_ctx(ctx) {
            Some(s) => s,
            None => {
                set_out(ctx, "redis-auth-check: not reachable");
                return 0;
            }
        };
        let sent = send_all(&mut s, format!("AUTH {}\r\n", w).as_bytes()).is_ok();
        let resp = if sent { recv_all(&mut s, 256) } else { Vec::new() };
        drop(s);
        if sent && !resp.is_empty() && resp[0] == b'+' {
            set_out(ctx, &format!("redis-auth-check: password '{}' ACCEPTED (verify)", w));
            return 0;
        }
    }
    set_out(ctx, "redis-auth-check: all 5 default passwords rejected");
    0
}
