/* mysql-info-3 - MySQL handshake banner. */
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
        ar_out(ctx, "MySQL info: no connection");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), 800);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "MySQL info: no banner");
        return 0;
    }
    ar_clean(resp);
    ar_out(ctx, "MySQL info: %.200s", resp);
    return 0;
}
