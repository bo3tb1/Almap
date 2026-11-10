/* cloud-azure-imds-check-4 - Azure IMDS instance metadata exposure
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
    n = ar_http_request(ctx, "GET", "/metadata/instance?api-version=2021-02-01", "169.254.169.254", "Metadata: true\\r\\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "cloud-azure-imds-check-4: no response from metadata endpoint");
        return 0;
    }
    ar_out(ctx, "cloud-azure-imds-check-4: GET /metadata/instance?api-version=20... [%d]%s", ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (metadata EXPOSED; verify)" : "");
    return 0;
}
