/* iot-pjlink-info-5 - PJLink projector info probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x25, 0x31, 0x49, 0x4e, 0x46, 0x4f, 0x20, 0x3f, 0x0d,
    };
    char resp[4096];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "iot-pjlink-info-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "iot-pjlink-info-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "iot-pjlink-info-5: no response");
        return 0;
    }
    ar_clean(resp);
    if (ar_contains_ci(resp, "%1INFO")) {
        ar_out(ctx, "iot-pjlink-info-5: detected");
    } else {
        ar_out(ctx, "iot-pjlink-info-5: not detected");
    }
    return 0;
}
