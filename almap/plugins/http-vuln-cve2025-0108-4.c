/* http-vuln-cve2025-0108-4 - PAN-OS management auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/unauth/php/change_password.php", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2025-0108-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "PAN-OS")) {
        ar_out(ctx, "VULNERABLE: /unauth/php/change_password.php [%d] (CVE-2025-0108)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2025-0108 (/unauth/php/change_password.php [%d])", ar_http_status(resp));
    }
    return 0;
}
