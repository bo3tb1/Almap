/* http-vuln-cve2022-37042-4 - Zimbra SOAP auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/service/soap", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-37042-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Zimbra")) {
        ar_out(ctx, "VULNERABLE: /service/soap [%d] (CVE-2022-37042)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-37042 (/service/soap [%d])", ar_http_status(resp));
    }
    return 0;
}
