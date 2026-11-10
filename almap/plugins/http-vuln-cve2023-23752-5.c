/* http-vuln-cve2023-23752-5 - Joomla CVE-2023-23752 config probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/api/index.php/v1/config/application?public=true", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2023-23752-5: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "\"data\"")) {
        ar_out(ctx, "http-vuln-cve2023-23752-5: detected (HTTP %d)", ar_http_status(resp));
    } else {
        ar_out(ctx, "http-vuln-cve2023-23752-5: not detected (HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
