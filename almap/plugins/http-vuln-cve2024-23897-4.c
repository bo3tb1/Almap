/* http-vuln-cve2024-23897-4 - Jenkins CLI arbitrary file read probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/cli", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-23897-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Jenkins")) {
        ar_out(ctx, "VULNERABLE: /cli [%d] (CVE-2024-23897)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-23897 (/cli [%d])", ar_http_status(resp));
    }
    return 0;
}
