/* http-vuln-cve2024-27198-4 - JetBrains TeamCity auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/app/rest/users", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-27198-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "TeamCity")) {
        ar_out(ctx, "VULNERABLE: /app/rest/users [%d] (CVE-2024-27198)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-27198 (/app/rest/users [%d])", ar_http_status(resp));
    }
    return 0;
}
