/* http-vuln-cve2023-3519-4 - Citrix ADC unauthenticated RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/vpn/../vpns/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-3519-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Citrix")) {
        ar_out(ctx, "VULNERABLE: /vpn/../vpns/ [%d] (CVE-2023-3519)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-3519 (/vpn/../vpns/ [%d])", ar_http_status(resp));
    }
    return 0;
}
