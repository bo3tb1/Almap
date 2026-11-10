/* http-vuln-cve2023-27350-4 - PaperCut NG auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/app", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-27350-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "PaperCut")) {
        ar_out(ctx, "VULNERABLE: /app [%d] (CVE-2023-27350)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-27350 (/app [%d])", ar_http_status(resp));
    }
    return 0;
}
