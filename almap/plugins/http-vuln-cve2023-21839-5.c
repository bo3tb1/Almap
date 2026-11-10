/* http-vuln-cve2023-21839-5 - WebLogic CVE-2023-21839 T3 probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x74, 0x33, 0x20, 0x31, 0x32, 0x2e, 0x32, 0x2e, 0x31, 0x0a, 0x41, 0x53,
        0x3a, 0x32, 0x35, 0x35, 0x0a, 0x48, 0x4c, 0x3a, 0x31, 0x39, 0x0a, 0x4d,
        0x53, 0x3a, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x0a, 0x50,
        0x55, 0x3a, 0x74, 0x33, 0x3a, 0x2f, 0x2f, 0x31, 0x32, 0x37, 0x2e, 0x30,
        0x2e, 0x30, 0x2e, 0x31, 0x3a, 0x37, 0x30, 0x30, 0x31, 0x0a, 0x0a,
    };
    char resp[4096];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "http-vuln-cve2023-21839-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "http-vuln-cve2023-21839-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-21839-5: no response");
        return 0;
    }
    ar_clean(resp);
    if (ar_contains_ci(resp, "HELO")) {
        ar_out(ctx, "http-vuln-cve2023-21839-5: detected");
    } else {
        ar_out(ctx, "http-vuln-cve2023-21839-5: not detected");
    }
    return 0;
}
