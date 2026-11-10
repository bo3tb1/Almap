/* http-vuln-cve2021-22986-4 - F5 BIG-IP iControl RCE probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/mgmt/shared/authn/login", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2021-22986-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "F5")) {
        ar_out(ctx, "VULNERABLE: /mgmt/shared/authn/login [%d] (CVE-2021-22986)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2021-22986 (/mgmt/shared/authn/login [%d])", ar_http_status(resp));
    }
    return 0;
}
