/* http-vuln-cve2025-1974-4 - Ingress NGINX admission webhook probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL, "Admission-Review-API: true\r\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2025-1974-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: / [%d] (CVE-2025-1974; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
