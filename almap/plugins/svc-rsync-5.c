/* svc-rsync-5 - rsync daemon banner probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[2048];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "svc-rsync-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "svc-rsync-5: no banner");
        return 0;
    }
    ar_clean(resp);
    if (ar_contains_ci(resp, "@RSYNCD")) {
        ar_out(ctx, "svc-rsync-5: detected: %.180s", resp);
    } else {
        ar_out(ctx, "svc-rsync-5: banner %.180s", resp);
    }
    return 0;
}
