/* svc-afp-5 - AFP service reachability probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "svc-afp-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    close(fd);
    ar_out(ctx, "svc-afp-5: service reachable on TCP %d", ctx->port);
    return 0;
}
