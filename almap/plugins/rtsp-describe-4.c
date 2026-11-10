/* rtsp-describe-4 - RTSP DESCRIBE stream probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char ip[32];
    char req[256];
    char resp[2048];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    as_ip_text(ctx->target_ip, ip, sizeof(ip));
    n = snprintf(req, sizeof(req),
                 "DESCRIBE rtsp://%s:%d/ RTSP/1.0\r\nCSeq: 1\r\n"
                 "User-Agent: ALmap\r\n\r\n", ip, ctx->port);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "rtsp-describe-4: not reachable");
        return 0;
    }
    if (as_send_all(fd, req, (size_t)n, ctx->timeout_ms) != 0 ||
        (n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms)) <= 0) {
        close(fd);
        ar_out(ctx, "rtsp-describe-4: no RTSP reply");
        return 0;
    }
    close(fd);
    ar_clean(resp);
    ar_out(ctx, "rtsp-describe-4: %.200s", resp);
    return 0;
}
