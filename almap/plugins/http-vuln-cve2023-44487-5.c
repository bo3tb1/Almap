/* http-vuln-cve2023-44487-5 - HTTP/2 Rapid Reset CVE-2023-44487 probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    static const unsigned char req[] = {
        0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50,
        0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a, 0x53, 0x4d,
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x00, 0x00
    };
    char resp[2048];
    int fd;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    fd = as_connect(ctx);
    if (fd < 0) {
        ar_out(ctx, "http-vuln-cve2023-44487-5: TCP %d not reachable", ctx->port);
        return 0;
    }
    if (as_send_all(fd, req, sizeof(req), ctx->timeout_ms) != 0) {
        close(fd);
        ar_out(ctx, "http-vuln-cve2023-44487-5: send failed");
        return 0;
    }
    n = as_recv_all(fd, resp, sizeof(resp), ctx->timeout_ms);
    close(fd);
    if (n >= 9 && (unsigned char)resp[3] == 0x04) {
        ar_out(ctx, "http-vuln-cve2023-44487-5: HTTP/2 SETTINGS seen");
    } else {
        ar_out(ctx, "http-vuln-cve2023-44487-5: no HTTP/2 SETTINGS (%d bytes)", n);
    }
    return 0;
}
