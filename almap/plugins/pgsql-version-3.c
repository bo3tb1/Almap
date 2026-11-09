/* pgsql-version-3 - PostgreSQL SSLRequest version probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[8] = {
        0, 0, 0, 8, 4, 0xd2, 0x16, 0x2f
    };
    unsigned char resp[1];
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "PostgreSQL version: no connection");
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0 ||
        as_recv_exact(fd, resp, 1, ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "PostgreSQL version: no SSLRequest response");
        return 0;
    }
    close(fd);
    if (resp[0] == 'S') {
        ar_out(ctx, "PostgreSQL version: SSL supported");
    } else if (resp[0] == 'N') {
        ar_out(ctx, "PostgreSQL version: SSL refused");
    } else {
        ar_out(ctx, "PostgreSQL version: response 0x%02x", resp[0]);
    }
    return 0;
}
