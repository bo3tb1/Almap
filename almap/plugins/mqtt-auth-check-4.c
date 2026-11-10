/* mqtt-auth-check-4 - MQTT default-credential check (fixed 5-entry dict)
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    /* CONNECT with username+password flags (0xc2); user=pass=word */
    static const char *words[5] = { "admin", "password", "root", "test", "guest" };
    unsigned char pkt[64];
    unsigned char resp[64];
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    for (i = 0; i < 5; i++) {
        size_t wl = strlen(words[i]);
        size_t o = 0;
        int fd;
        pkt[o++] = 0x10;
        pkt[o++] = (unsigned char)(12 + 2 + wl + 2 + wl);
        pkt[o++] = 0x00; pkt[o++] = 0x04;
        memcpy(pkt + o, "MQTT", 4); o += 4;
        pkt[o++] = 0x04; pkt[o++] = 0xc2; pkt[o++] = 0x00; pkt[o++] = 0x3c;
        pkt[o++] = 0x00; pkt[o++] = 0x00;                 /* empty client id */
        pkt[o++] = 0x00; pkt[o++] = (unsigned char)wl;
        memcpy(pkt + o, words[i], wl); o += wl;
        pkt[o++] = 0x00; pkt[o++] = (unsigned char)wl;
        memcpy(pkt + o, words[i], wl); o += wl;
        fd = as_connect(ctx);
        if (fd < 0) { ar_out(ctx, "mqtt-auth-check: not reachable"); return 0; }
        if (as_send_all(fd, pkt, o, ctx->timeout_ms) == 0 &&
            as_recv_all(fd, (char *)resp, sizeof(resp), ctx->timeout_ms) >= 4 &&
            resp[0] == 0x20 && resp[3] == 0) {
            close(fd);
            ar_out(ctx, "mqtt-auth-check: %s:%s ACCEPTED (verify)", words[i], words[i]);
            return 0;
        }
        close(fd);
    }
    ar_out(ctx, "mqtt-auth-check: all 5 default pairs rejected");
    return 0;
}
