/* http-vuln-cve2025-31644-4 - Cisco web UI command injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/webui/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2025-31644-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Cisco")) {
        ar_out(ctx, "VULNERABLE: /webui/ [%d] (CVE-2025-31644)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2025-31644 (/webui/ [%d])", ar_http_status(resp));
    }
    return 0;
}
