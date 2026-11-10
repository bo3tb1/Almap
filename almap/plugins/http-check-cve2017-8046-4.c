/* http-check-cve2017-8046-4 - Spring Data REST PATCH SpEL injection
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
    n = ar_http_request(ctx, "PATCH", "/customers/1", NULL, NULL, "[{\"op\":\"replace\",\"path\":\"T(java.lang.Runtime)\",\"value\":\"x\"}]",
                        "application/json-patch+json", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-check-cve2017-8046-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: PATCH /customers/1 [%d] (CVE2017-8046; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
