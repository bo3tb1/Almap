/* http-vhosts-3 - compare three Host header values */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let hosts = ["admin", "test", "localhost"];
    let mut found = 0usize;
    for host in hosts.iter() {
        let resp = match http_request(ctx, "GET", "/", Some(*host), "", "", None, 4096) {
            Some(r) if !r.is_empty() => r,
            _ => continue,
        };
        append_out(ctx, &format!("{}{}={}",
            if found == 0 { "vhosts: " } else { ", " }, host, http_status(&resp)));
        found += 1;
    }
    if found == 0 {
        set_out(ctx, "vhosts: no responses");
    }
    0
}
