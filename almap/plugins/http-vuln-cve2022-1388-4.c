/* http-vuln-cve2022-1388-4 - F5 BIG-IP iControl auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/mgmt/tm/util/bash", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-1388-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "F5")) {
        ar_out(ctx, "VULNERABLE: /mgmt/tm/util/bash [%d] (CVE-2022-1388)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-1388 (/mgmt/tm/util/bash [%d])", ar_http_status(resp));
    }
    return 0;
}
