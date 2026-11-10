/* mqtt-connack-4 - MQTT CONNACK return-code decoder
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char connect[19] = {
        0x10, 0x11, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02,
        0x00, 0x3c, 0x00, 0x05, 0x41, 0x4c, 0x6d, 0x61, 0x70
    };
    static const char *rc[6] = {
        "accepted", "bad proto version", "id rejected",
        "server unavailable", "bad user/pass", "not authorized"
    };
    unsigned char resp[64];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0 || as_send_all(fd, connect, sizeof(connect), ctx->timeout_ms) != 0 ||
        (n = as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms)) < 4) {
        if (fd >= 0) close(fd);
        ar_out(ctx, "mqtt-connack: no response");
        return 0;
    }
    close(fd);
    ar_out(ctx, "mqtt-connack: rc=%d (%s)", resp[3],
           (resp[3] < 6) ? rc[resp[3]] : "unknown");
    return 0;
}
