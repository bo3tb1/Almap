/* rtsp-url-brute-4 - RTSP common stream-path check (fixed 5-entry list)
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const char *paths[5] = {
        "/live.sdp", "/stream", "/h264", "/video", "/0"
    };
    char ip[32];
    char req[256];
    char resp[1024];
    int i;

    if (!ar_valid(ctx)) {
        return 1;
    }
    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    for (i = 0; i < 5; i++) {
        int fd = as_connect(ctx);
        int n;
        if (fd < 0) {
            ar_out(ctx, "rtsp-url-brute: not reachable");
            return 0;
        }
        n = snprintf(req, sizeof(req),
                     "DESCRIBE rtsp://%s:%d%s RTSP/1.0\r\nCSeq: 1\r\n\r\n",
                     ip, ctx->port, paths[i]);
        if (n > 0 && as_send_all(fd, req, (size_t)n, ctx->timeout_ms) == 0 &&
            as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms) > 0 &&
            ar_starts_ci(resp, "RTSP/1.0 200")) {
            close(fd);
            ar_out(ctx, "rtsp-url-brute: %s -> 200 OK (verify)", paths[i]);
            return 0;
        }
        close(fd);
    }
    ar_out(ctx, "rtsp-url-brute: none of 5 common paths returned 200");
    return 0;
}
