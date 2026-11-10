/* http-vuln-cve2022-22965-4 - Spring4Shell data binding probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-22965-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Spring")) {
        ar_out(ctx, "VULNERABLE: / [%d] (CVE-2022-22965)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-22965 (/ [%d])", ar_http_status(resp));
    }
    return 0;
}
