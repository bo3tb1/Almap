/* http-vuln-cve2021-34473-4 - Exchange ProxyShell path confusion probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/autodiscover/autodiscover.json?@test.com=/mapi/nspi", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2021-34473-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Exchange")) {
        ar_out(ctx, "VULNERABLE: /autodiscover/autodiscover.json?@test.com=/mapi/nspi [%d] (CVE-2021-34473)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2021-34473 (/autodiscover/autodiscover.json?@test.com=/mapi/nspi [%d])", ar_http_status(resp));
    }
    return 0;
}
