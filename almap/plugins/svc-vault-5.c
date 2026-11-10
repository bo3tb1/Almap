/* svc-vault-5 - HashiCorp Vault health probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/v1/sys/health", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "svc-vault-5: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "initialized")) {
        ar_out(ctx, "svc-vault-5: detected (HTTP %d)", ar_http_status(resp));
    } else {
        ar_out(ctx, "svc-vault-5: not detected (HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
