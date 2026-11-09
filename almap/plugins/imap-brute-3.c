/* imap-brute-3 - five fixed IMAP LOGIN attempts. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *users[] = {
        "admin", "root", "password", "admin", "root"
    };
    static const char *passes[] = {
        "admin", "root", "password", "password", "password"
    };
    char cmd[160];
    char resp[512];
    int fd;
    int found = 0;
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "IMAP brute: no connection");
        return 0;
    }
    for (i = 0; i < 5; i++) {
        (void)snprintf(cmd, sizeof(cmd), "a%d LOGIN %s %s\r\n",
                       i + 1, users[i], passes[i]);
        if (as_send_all(fd, cmd, strlen(cmd), ctx->timeout_ms) != 0) {
            break;
        }
        if (as_recv_line(fd, resp, sizeof(resp), 800) <= 0) {
            break;
        }
        if (ar_contains_ci(resp, "OK")) {
            ar_append(ctx, "%s%s:%s", (found == 0) ?
                      "IMAP valid credentials: " : ", ",
                      users[i], passes[i]);
            found++;
            break;
        }
    }
    close(fd);
    if (found == 0) {
        ar_out(ctx, "IMAP brute: no valid credentials in 5 attempts");
    }
    return 0;
}
