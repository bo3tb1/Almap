/* http-vuln-cve2024-3400-4 - PAN-OS GlobalProtect command injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/ssl-vpn/hipreport.esp", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-3400-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "GlobalProtect")) {
        ar_out(ctx, "VULNERABLE: /ssl-vpn/hipreport.esp [%d] (CVE-2024-3400)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-3400 (/ssl-vpn/hipreport.esp [%d])", ar_http_status(resp));
    }
    return 0;
}
