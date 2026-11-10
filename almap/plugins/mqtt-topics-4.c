/* mqtt-topics-4 - MQTT wildcard SUBSCRIBE probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char connect[19] = {
        0x10, 0x11, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02,
        0x00, 0x3c, 0x00, 0x05, 0x41, 0x4c, 0x6d, 0x61, 0x70
    };
    /* SUBSCRIBE packet id=1 to topic "#" qos0 */
    static const unsigned char sub[8] = {
        0x82, 0x06, 0x00, 0x01, 0x00, 0x01, 0x23, 0x00
    };
    unsigned char resp[64];
    int fd;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0 || as_send_all(fd, connect, sizeof(connect), ctx->timeout_ms) != 0 ||
        as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms) < 4) {
        if (fd >= 0) close(fd);
        ar_out(ctx, "mqtt-topics: no CONNACK");
        return 0;
    }
    if (as_send_all(fd, sub, sizeof(sub), ctx->timeout_ms) == 0 &&
        as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms) >= 4 &&
        resp[0] == 0x90) {
        close(fd);
        ar_out(ctx, "mqtt-topics: SUBACK for '#' (anon subscribe allowed; verify)");
        return 0;
    }
    close(fd);
    ar_out(ctx, "mqtt-topics: wildcard subscribe refused");
    return 0;
}
