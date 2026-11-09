/* oracle-tns-info-3 - Oracle TNS listener information probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "Oracle TNS info: not reachable");
        return 0;
    }
    close(fd);
    ar_out(ctx, "Oracle TNS info: service reachable on port %d", ctx->port);
    return 0;
}
