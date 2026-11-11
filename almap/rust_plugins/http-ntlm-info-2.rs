/* http-ntlm-info-2 - detect NTLM authentication info. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let mut val = String::new();
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "GET", "/", None, "Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n", "", None, 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "NTLM info: no response"); return 0; }
};
val = http_header(&resp, "WWW-Authenticate").unwrap_or_default();
if (!val.is_empty() && contains_ci(&val, "NTLM")) {
    set_out(ctx, &format!("NTLM info: {}", val));
} else {
    set_out(ctx, &format!("NTLM info: not advertised (HTTP {})", http_status(&resp)));
}
0
}
