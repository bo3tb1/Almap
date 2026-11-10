/* http-vuln-cve2022-47966-4 - Zoho ManageEngine SAML RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-47966-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Zoho")) {
        ar_out(ctx, "VULNERABLE: / [%d] (CVE-2022-47966)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-47966 (/ [%d])", ar_http_status(resp));
    }
    return 0;
}
