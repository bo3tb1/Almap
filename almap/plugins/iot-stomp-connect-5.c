/* iot-stomp-connect-5 - STOMP CONNECT probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x43, 0x4f, 0x4e, 0x4e, 0x45, 0x43, 0x54, 0x0a, 0x61, 0x63, 0x63, 0x65,
        0x70, 0x74, 0x2d, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3a, 0x31,
        0x2e, 0x32, 0x0a, 0x68, 0x6f, 0x73, 0x74, 0x3a, 0x61, 0x6c, 0x6d, 0x61,
        0x70, 0x0a, 0x0a, 0x00,
    };
    char resp[4096];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "iot-stomp-connect-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "iot-stomp-connect-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "iot-stomp-connect-5: no response");
        return 0;
    }
    ar_clean(resp);
    if (ar_contains_ci(resp, "CONNECTED")) {
        ar_out(ctx, "iot-stomp-connect-5: detected");
    } else {
        ar_out(ctx, "iot-stomp-connect-5: not detected");
    }
    return 0;
}
