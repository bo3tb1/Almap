/* http-vuln-cve2021-38647-5 - OMIGOD CVE-2021-38647 WSMan probe * Use only on networks you own or have permission to scan. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
let port = unsafe { (*ctx).port };
let mut resp = String::new();
resp = match http_request(ctx, "POST", "/wsman", None, "", "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body><p:Identify xmlns:p=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\"/></s:Body></s:Envelope>", Some("application/soap+xml"), 8192) {
    Some(r) if !r.is_empty() => r,
    _ => { set_out(ctx, "http-vuln-cve2021-38647-5: no HTTP response"); return 0; }
};
if contains_ci(&resp, "IdentifyResponse") {
    set_out(ctx, &format!("http-vuln-cve2021-38647-5: detected (HTTP {})", http_status(&resp)));
} else {
    set_out(ctx, &format!("http-vuln-cve2021-38647-5: not detected (HTTP {})", http_status(&resp)));
}
0
}
