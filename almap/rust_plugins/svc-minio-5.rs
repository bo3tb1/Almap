/* svc-minio-5 - MinIO health probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/minio/health/live", None, "", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "svc-minio-5: no HTTP response"); return 0; }
};
set_out(ctx, &format!("svc-minio-5: HTTP {}, {} bytes", http_status(&resp), resp.len()));
0
}
