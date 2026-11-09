/* oracle-listener-3 - Oracle listener exposure probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "Oracle listener: not reachable");
        return 0;
    }
    close(fd);
    ar_out(ctx, "Oracle listener: service reachable on port %d", ctx->port);
    return 0;
}
