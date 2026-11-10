/* http-traceroute-2 - count proxy hops from response headers */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let resp = match http_request(ctx, "GET", "/", None, "", "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "HTTP traceroute: no response"); return 0; }
    };
    let low = resp.to_ascii_lowercase();
    let mut hops = low.matches("\nvia:").count();
    if low.contains("x-forwarded-for") { hops += 1; }
    set_out(ctx, &format!("HTTP traceroute: {} proxy hop(s) indicated", hops));
    0
}
