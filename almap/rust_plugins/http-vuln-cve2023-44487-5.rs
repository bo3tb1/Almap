/* http-vuln-cve2023-44487-5 - HTTP/2 Rapid Reset CVE-2023-44487 probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut s = match connect_ctx(ctx) {
    Some(s) => s,
    None => { set_out(ctx, &format!("http-vuln-cve2023-44487-5: TCP {} not reachable", port)); return 0; }
};
if send_all(&mut s, &[80, 82, 73, 32, 42, 32, 72, 84, 84, 80, 47, 50, 46, 48, 13, 10, 13, 10, 83, 77, 13, 10, 13, 10, 0, 0, 0, 4, 0, 0, 0, 0, 0]).is_err() {
    set_out(ctx, "http-vuln-cve2023-44487-5: send failed");
    return 0;
}
let buf = recv_all(&mut s, 4096);
if buf.is_empty() {
    set_out(ctx, "http-vuln-cve2023-44487-5: no response");
    return 0;
}
let resp = clean(&String::from_utf8_lossy(&buf));
let rb = &buf;
let n = buf.len();
if buf.len() > 3 && buf[3] == 4 {
    set_out(ctx, "http-vuln-cve2023-44487-5: HTTP/2 SETTINGS seen");
} else {
    set_out(ctx, &format!("http-vuln-cve2023-44487-5: no HTTP/2 SETTINGS ({} bytes)", resp.len()));
}
0
}
