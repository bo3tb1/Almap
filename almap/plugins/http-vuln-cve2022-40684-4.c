/* http-vuln-cve2022-40684-4 - Fortinet FortiOS auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/api/v2/cmdb/system/admin", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-40684-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Fortinet")) {
        ar_out(ctx, "VULNERABLE: /api/v2/cmdb/system/admin [%d] (CVE-2022-40684)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-40684 (/api/v2/cmdb/system/admin [%d])", ar_http_status(resp));
    }
    return 0;
}
