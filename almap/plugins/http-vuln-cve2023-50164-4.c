/* http-vuln-cve2023-50164-4 - Apache Struts path traversal probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/upload.action", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-50164-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Struts")) {
        ar_out(ctx, "VULNERABLE: /upload.action [%d] (CVE-2023-50164)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-50164 (/upload.action [%d])", ar_http_status(resp));
    }
    return 0;
}
