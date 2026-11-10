/* http-check-cve2017-12149-4 - JBoss ReadOnlyAccessFilter deserialization
 * (CVE detection probe; benign request, verify out-of-band).
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/invoker/readonly", NULL, NULL, NULL,
                        NULL, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-check-cve2017-12149-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: POST /invoker/readonly [%d] (CVE2017-12149; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
