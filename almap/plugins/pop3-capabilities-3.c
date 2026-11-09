/* pop3-capabilities-3 - POP3 banner and capability probe. */
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
        ar_out(ctx, "POP3 capabilities: no connection");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), 800);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "POP3 capabilities: no banner");
        return 0;
    }
    ar_clean(resp);
    ar_out(ctx, "POP3 capabilities: %.200s", resp);
    return 0;
}
