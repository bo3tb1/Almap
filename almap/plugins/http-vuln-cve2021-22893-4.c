/* http-vuln-cve2021-22893-4 - Pulse Secure auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/dana-na/auth/url_default/welcome.cgi", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2021-22893-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Pulse")) {
        ar_out(ctx, "VULNERABLE: /dana-na/auth/url_default/welcome.cgi [%d] (CVE-2021-22893)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2021-22893 (/dana-na/auth/url_default/welcome.cgi [%d])", ar_http_status(resp));
    }
    return 0;
}
