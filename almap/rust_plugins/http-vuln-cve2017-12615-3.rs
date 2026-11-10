/* http-vuln-cve2017-12615-3 - CVE-2017-12615 Tomcat PUT probe */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let resp = match http_request(ctx, "PUT", "/almap.jsp/", None, "\r\n",
                                  "<% out.println(\"ALMAP\"); %>",
                                  Some("text/plain"), 4096) {
        Some(r) => r,
        _ => String::new(),
    };
    let code = http_status(&resp);
    if !resp.is_empty() && (code == 200 || code == 201 || code == 204) {
        set_out(ctx, &format!(
            "potentially vulnerable: CVE-2017-12615 Tomcat PUT (HTTP {})", code));
    } else {
        set_out(ctx, &format!("not vulnerable: CVE-2017-12615 (HTTP {})", code));
    }
    0
}
