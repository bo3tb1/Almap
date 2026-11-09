/* oracle-enum-users-3 - Oracle user enumeration probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "Oracle users: not reachable");
        return 0;
    }
    close(fd);
    ar_out(ctx, "Oracle users: service reachable on port %d", ctx->port);
    return 0;
}
