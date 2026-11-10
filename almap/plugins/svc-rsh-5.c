/* svc-rsh-5 - rsh service probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x72, 0x6f, 0x6f, 0x74, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x69, 0x64,
        0x00,
    };
    char resp[4096];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "svc-rsh-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "svc-rsh-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "svc-rsh-5: no response");
        return 0;
    }
    ar_clean(resp);
    ar_out(ctx, "svc-rsh-5: %.220s", resp);
    return 0;
}
