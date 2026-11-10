/* kubelet-pods-4 - Kubelet read-only pods endpoint
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/pods", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "kubelet-pods-4: no HTTP response on port %d", ctx->port);
        return 0;
    }
    ar_out(ctx, "kubelet-pods-4: GET /pods [%d]%s", ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (open; verify)" : "");
    return 0;
}
