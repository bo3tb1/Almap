/* redis-auth-check-4 - Redis AUTH default-credential / no-auth check.
 * Uses a fixed 5-entry test dictionary. Benign: sends AUTH and PING.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *words[5] = { "admin", "password", "root", "test", "guest" };
    char resp[256];
    char cmd[64];
    int i;
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        int n = snprintf(cmd, sizeof(cmd), "AUTH %s\r\n", words[i]);
        if (n < 0 || (size_t)n >= sizeof(cmd)) {
            continue;
        }
        fd = as_connect(ctx);
        if (fd < 0) {
            ar_out(ctx, "redis-auth-check: not reachable");
            return 0;
        }
        if (as_send_all(fd, cmd, (size_t)n, ctx->timeout_ms) == 0 &&
            as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms) > 0 &&
            resp[0] == '+') {
            close(fd);
            ar_out(ctx, "redis-auth-check: password '%s' ACCEPTED (verify)", words[i]);
            return 0;
        }
        close(fd);
    }
    ar_out(ctx, "redis-auth-check: all 5 default passwords rejected");
    return 0;
}
