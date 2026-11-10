/* http-vuln-cve2023-38646-4 - Metabase pre-auth RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/api/session/properties", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-38646-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Metabase")) {
        ar_out(ctx, "VULNERABLE: /api/session/properties [%d] (CVE-2023-38646)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-38646 (/api/session/properties [%d])", ar_http_status(resp));
    }
    return 0;
}
