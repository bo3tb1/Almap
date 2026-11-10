/* iot-amqp-handshake-5 - AMQP 0-9-1 protocol-header probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x41, 0x4d, 0x51, 0x50, 0x00, 0x00, 0x09, 0x01,
    };
    char resp[4096];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "iot-amqp-handshake-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "iot-amqp-handshake-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "iot-amqp-handshake-5: no response");
        return 0;
    }
    if (n >= 4 && memcmp(resp, "AMQP", 4) == 0) {
        ar_out(ctx, "iot-amqp-handshake-5: expected reply seen (%d bytes)", n);
    } else {
        ar_out(ctx, "iot-amqp-handshake-5: unexpected reply (%d bytes)", n);
    }
    return 0;
}
