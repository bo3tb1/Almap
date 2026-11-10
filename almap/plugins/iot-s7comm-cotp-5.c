/* iot-s7comm-cotp-5 - S7comm COTP connection-request probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1,
        0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x0a,
    };
    char resp[4096];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "iot-s7comm-cotp-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "iot-s7comm-cotp-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "iot-s7comm-cotp-5: no response");
        return 0;
    }
    if (n >= 4 && (unsigned char)resp[0] == 0x03) {
        ar_out(ctx, "iot-s7comm-cotp-5: expected reply seen (%d bytes)", n);
    } else {
        ar_out(ctx, "iot-s7comm-cotp-5: unexpected reply (%d bytes)", n);
    }
    return 0;
}
