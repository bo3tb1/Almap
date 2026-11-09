/* redis-brute-3 - five fixed Redis AUTH attempts. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *passes[] = {
        "admin", "root", "password", "123456", "redis"
    };
    char cmd[64];
    char resp[256];
    int fd;
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "Redis brute: no connection");
        return 0;
    }
    for (i = 0; i < 5; i++) {
        (void)snprintf(cmd, sizeof(cmd), "AUTH %s\r\n", passes[i]);
        if (as_send_all(fd, cmd, strlen(cmd), ctx->timeout_ms) != 0) {
            break;
        }
        if (as_recv_line(fd, resp, sizeof(resp), 800) <= 0) {
            break;
        }
        if (strstr(resp, "+OK") != NULL) {
            ar_append(ctx, "%s%s", (found == 0) ?
                      "Redis valid password: " : ", ", passes[i]);
            found++;
            break;
        }
    }
    close(fd);
    if (found == 0) {
        ar_out(ctx, "Redis brute: no valid password in 5 attempts");
    }
    return 0;
}
