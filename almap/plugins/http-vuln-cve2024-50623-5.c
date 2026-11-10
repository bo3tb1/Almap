/* http-vuln-cve2024-50623-5 - Cleo CVE-2024-50623 probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/Synchronization", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-50623-5: no HTTP response");
        return 0;
    }
    ar_out(ctx, "http-vuln-cve2024-50623-5: HTTP %d, %d bytes", ar_http_status(resp), n);
    return 0;
}
