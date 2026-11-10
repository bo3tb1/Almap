/* etcd-keys-4 - etcd v2 keyspace listing
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/v2/keys/?recursive=true", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "etcd-keys-4: no HTTP response on port %d", ctx->port);
        return 0;
    }
    ar_out(ctx, "etcd-keys-4: GET /v2/keys/?recursive=true [%d]%s", ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (open; verify)" : "");
    return 0;
}
