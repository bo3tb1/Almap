/* http-vuln-cve2025-24813-4 - Tomcat partial PUT RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/partial", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2025-24813-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Tomcat")) {
        ar_out(ctx, "VULNERABLE: /partial [%d] (CVE-2025-24813)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2025-24813 (/partial [%d])", ar_http_status(resp));
    }
    return 0;
}
