/* http-vuln-cve2024-21683-4 - Atlassian Confluence RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/rest/api/content", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-21683-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Confluence")) {
        ar_out(ctx, "VULNERABLE: /rest/api/content [%d] (CVE-2024-21683)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-21683 (/rest/api/content [%d])", ar_http_status(resp));
    }
    return 0;
}
