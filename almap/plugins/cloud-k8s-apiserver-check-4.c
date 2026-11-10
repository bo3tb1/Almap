/* cloud-k8s-apiserver-check-4 - Kubernetes API server version endpoint
 * Probes a well-known cloud metadata endpoint; benign GET/PUT.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/version", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "cloud-k8s-apiserver-check-4: no response from metadata endpoint");
        return 0;
    }
    ar_out(ctx, "cloud-k8s-apiserver-check-4: GET /version [%d]%s", ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (metadata EXPOSED; verify)" : "");
    return 0;
}
