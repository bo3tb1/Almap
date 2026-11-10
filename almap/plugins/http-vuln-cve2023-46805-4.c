/* http-vuln-cve2023-46805-4 - Ivanti ICS auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/api/v1/configuration/users", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-46805-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Ivanti")) {
        ar_out(ctx, "VULNERABLE: /api/v1/configuration/users [%d] (CVE-2023-46805)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-46805 (/api/v1/configuration/users [%d])", ar_http_status(resp));
    }
    return 0;
}
