/* pop3-brute-3 - five fixed POP3 USER/PASS attempts. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = {
        "admin", "root", "password", "admin", "root"
    };
    static const char *passes[] = {
        "admin", "root", "password", "password", "password"
    };
    char cmd[128];
    char resp[512];
    int fd;
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "POP3 brute: no connection");
        return 0;
    }
    for (i = 0; i < 5; i++) {
        (void)snprintf(cmd, sizeof(cmd), "USER %s\r\n", users[i]);
        if (as_send_all(fd, cmd, strlen(cmd), ctx->timeout_ms) != 0 ||
            as_recv_line(fd, resp, sizeof(resp), 800) <= 0) {
            break;
        }
        (void)snprintf(cmd, sizeof(cmd), "PASS %s\r\n", passes[i]);
        if (as_send_all(fd, cmd, strlen(cmd), ctx->timeout_ms) != 0 ||
            as_recv_line(fd, resp, sizeof(resp), 800) <= 0) {
            break;
        }
        if (strstr(resp, "+OK") != NULL) {
            ar_append(ctx, "%s%s:%s", (found == 0) ?
                      "POP3 valid credentials: " : ", ",
                      users[i], passes[i]);
            found++;
            break;
        }
    }
    close(fd);
    if (found == 0) {
        ar_out(ctx, "POP3 brute: no valid credentials in 5 attempts");
    }
    return 0;
}
