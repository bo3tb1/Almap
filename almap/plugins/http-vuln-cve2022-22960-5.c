/* http-vuln-cve2022-22960-5 - VMware Workspace ONE CVE-2022-22960 probe
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_get(ctx, "/catalog-portal/ui/oauth/verify?error=almap", resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-22960-5: no HTTP response");
        return 0;
    }
    ar_out(ctx, "http-vuln-cve2022-22960-5: HTTP %d, %d bytes", ar_http_status(resp), n);
    return 0;
}
