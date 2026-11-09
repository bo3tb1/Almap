/* http-vuln-cve2011-3192 - Apache Range header denial-of-service probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char range[1024];
    char resp[8192];
    char server[256];
    size_t o = 0;
    int i;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    o += (size_t)snprintf(range + o, sizeof(range) - o, "Range: bytes=");
    for (i = 0; i < 100 && o + 12 < sizeof(range); i++) {
        o += (size_t)snprintf(range + o, sizeof(range) - o,
                              "%s0-1", (i == 0) ? "" : ",");
    }
    o += (size_t)snprintf(range + o, sizeof(range) - o, "\r\n");
    n = ar_http_request(ctx, "GET", "/", NULL, range, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "CVE-2011-3192: no response");
        return 0;
    }
    (void)ar_http_header(resp, "Server", server, sizeof(server));
    if (ar_http_status(resp) == 206 &&
        (ar_http_header(resp, "Content-Range", server, sizeof(server)) ||
         ar_contains_ci(resp, "multipart/byteranges"))) {
        ar_out(ctx, "VULNERABLE: Apache Range header DoS CVE-2011-3192 (HTTP 206)");
    } else {
        ar_out(ctx, "not vulnerable: CVE-2011-3192 (HTTP %d)",
               ar_http_status(resp));
    }
    return 0;
}
