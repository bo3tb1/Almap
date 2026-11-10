/* redis-vuln-cve2022-0543-5 - Redis CVE-2022-0543 version probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    char *p;
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "redis-vuln-cve2022-0543-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, "INFO server\r\n", 13, ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "redis-vuln-cve2022-0543-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "redis-vuln-cve2022-0543-5: no INFO reply");
        return 0;
    }
    ar_clean(resp);
    p = strstr(resp, "redis_version:");
    if (p != NULL) {
        char *e = strpbrk(p, "\r\n");
        if (e != NULL) {
            *e = '\0';
        }
        ar_out(ctx, "redis-vuln-cve2022-0543-5: %s (verify patch level)", p);
    } else {
        ar_out(ctx, "redis-vuln-cve2022-0543-5: INFO reply did not expose version");
    }
    return 0;
}
