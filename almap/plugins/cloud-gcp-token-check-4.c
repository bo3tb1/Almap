/* cloud-gcp-token-check-4 - GCP default SA access-token endpoint
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
    n = ar_http_request(ctx, "GET", "/computeMetadata/v1/instance/service-accounts/default/token", "metadata.google.internal", "Metadata-Flavor: Google\\r\\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "cloud-gcp-token-check-4: no response from metadata endpoint");
        return 0;
    }
    ar_out(ctx, "cloud-gcp-token-check-4: GET /computeMetadata/v1/instance/serv... [%d]%s", ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (metadata EXPOSED; verify)" : "");
    return 0;
}
