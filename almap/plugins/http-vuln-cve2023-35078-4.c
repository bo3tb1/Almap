/* http-vuln-cve2023-35078-4 - Ivanti EPMM auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/mifs/aad/api/v2/authorized/users", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-35078-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Ivanti")) {
        ar_out(ctx, "VULNERABLE: /mifs/aad/api/v2/authorized/users [%d] (CVE-2023-35078)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-35078 (/mifs/aad/api/v2/authorized/users [%d])", ar_http_status(resp));
    }
    return 0;
}
