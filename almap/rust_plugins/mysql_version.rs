/* mysql_version - * plugins/mysql_version.c - NSE mysql-info analog (version only). * * Build: * gcc -shared -fPIC -o plugins/mysql_version.so plugins/mysql_v */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("mysql_version: TCP {} not reachable", port)); return 0; }
};
let buf = recv_exact(&mut s, 4096).unwrap_or_default();
if buf.is_empty() {
    set_out(ctx, "mysql_version: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
set_out(ctx, &format!("mysql_version: {}", &resp.chars().take(220).collect::<String>()));
0
}
