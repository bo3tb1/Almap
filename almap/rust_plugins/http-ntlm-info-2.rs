/* http-ntlm-info-2 - detect NTLM authentication info */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "GET", "/", None,
        "Authorization: NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=\r\n",
        "", None, 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "NTLM info: no response"); return 0; }
    };
    match http_header(&resp, "WWW-Authenticate") {
        Some(val) if contains_ci(&val, "NTLM") => {
            set_out(ctx, &format!("NTLM info: {}", val));
        }
        _ => set_out(ctx, &format!(
            "NTLM info: not advertised (HTTP {})", http_status(&resp))),
    }
    0
}
