/* http-vuln-cve2023-49103-5 - ownCloud CVE-2023-49103 phpinfo probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/apps/graphapi/vendor/microsoft/microsoft-graph/tests/GetPhpInfo.php", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-49103-5: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "phpinfo")) {
        ar_out(ctx, "http-vuln-cve2023-49103-5: detected (HTTP %d)", ar_http_status(resp));
    } else {
        ar_out(ctx, "http-vuln-cve2023-49103-5: not detected (HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
