/* http-vuln-cve2021-31166-5 - HTTP.sys CVE-2021-31166 probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL, "Accept-Encoding: gzip, gzip\r\n", NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2021-31166-5: no HTTP response");
        return 0;
    }
    ar_out(ctx, "http-vuln-cve2021-31166-5: HTTP %d, %d bytes", ar_http_status(resp), n);
    return 0;
}
