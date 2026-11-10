/* http-vuln-cve2023-4966-4 - Citrix Bleed session token leak probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/oauth/idp/.well-known/openid-configuration", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-4966-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Citrix")) {
        ar_out(ctx, "VULNERABLE: /oauth/idp/.well-known/openid-configuration [%d] (CVE-2023-4966)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-4966 (/oauth/idp/.well-known/openid-configuration [%d])", ar_http_status(resp));
    }
    return 0;
}
