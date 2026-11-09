/* redis-info-3 - Redis INFO command probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char probe[] = "INFO\r\n";
    char resp[4096];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "Redis info: no connection");
        return 0;
    }
    if (as_send_all(fd, probe, sizeof(probe) - 1, ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "Redis info: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), 800);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "Redis info: no response");
        return 0;
    }
    ar_clean(resp);
    if (ar_contains_ci(resp, "redis_version")) {
        ar_out(ctx, "Redis info: %.300s", resp);
    } else {
        ar_out(ctx, "Redis info: no match (%.100s)", resp);
    }
    return 0;
}
