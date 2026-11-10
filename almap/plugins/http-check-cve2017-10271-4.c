/* http-check-cve2017-10271-4 - Oracle WebLogic WLS-WSAT deserialization
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
    n = ar_http_request(ctx, "POST", "/wls-wsat/CoordinatorPortType", NULL, NULL, NULL,
                        "text/xml", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-check-cve2017-10271-4: no HTTP response");
        return 0;
    }
    ar_out(ctx, "probe sent: POST /wls-wsat/CoordinatorPortType [%d] (CVE2017-10271; verify out-of-band)",
           ar_http_status(resp));
    return 0;
}
