/* http-vuln-cve2022-41352-4 - Zimbra tar path traversal probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/service/extension/backup/mboximport", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-41352-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Zimbra")) {
        ar_out(ctx, "VULNERABLE: /service/extension/backup/mboximport [%d] (CVE-2022-41352)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-41352 (/service/extension/backup/mboximport [%d])", ar_http_status(resp));
    }
    return 0;
}
