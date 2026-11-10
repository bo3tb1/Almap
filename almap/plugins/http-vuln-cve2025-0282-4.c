/* http-vuln-cve2025-0282-4 - Ivanti Connect Secure stack probe. */
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
        ar_out(ctx, "http-vuln-cve2025-0282-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Ivanti")) {
        ar_out(ctx, "VULNERABLE: /dana-na/auth/url_default/welcome.cgi [%d] (CVE-2025-0282)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2025-0282 (/dana-na/auth/url_default/welcome.cgi [%d])", ar_http_status(resp));
    }
    return 0;
}
