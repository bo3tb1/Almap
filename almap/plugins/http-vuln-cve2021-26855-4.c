/* http-vuln-cve2021-26855-4 - Exchange ProxyLogon SSRF probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/owa/auth/logon.aspx", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2021-26855-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Exchange")) {
        ar_out(ctx, "VULNERABLE: /owa/auth/logon.aspx [%d] (CVE-2021-26855)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2021-26855 (/owa/auth/logon.aspx [%d])", ar_http_status(resp));
    }
    return 0;
}
