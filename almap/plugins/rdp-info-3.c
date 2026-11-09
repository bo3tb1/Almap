/* rdp-info-3 - RDP service exposure probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "RDP info: not reachable");
        return 0;
    }
    close(fd);
    ar_out(ctx, "RDP info: service reachable on port %d", ctx->port);
    return 0;
}
