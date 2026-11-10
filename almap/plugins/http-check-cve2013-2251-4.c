/* http-check-cve2013-2251-4 - Apache Struts2 S2-016 action: prefix
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
    n = ar_http_request(ctx, "GET", "/index.action?action:%25%7B1%2B1%7D", NULL, NULL, NULL,
                        NULL, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-check-cve2013-2251-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: GET /index.action?action:%25%7B1%2B1%7D [%d] (CVE2013-2251; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
