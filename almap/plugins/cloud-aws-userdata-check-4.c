/* cloud-aws-userdata-check-4 - AWS EC2 IMDS user-data exposure check.
 * Probes the well-known user-data endpoint; benign GET.
 * Use only on networks you own or have permission to scan.
 */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/latest/user-data/", "169.254.169.254",
                        NULL, NULL, NULL, resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "cloud-aws-userdata-check: no response from metadata endpoint");
        return 0;
    }
    ar_out(ctx, "cloud-aws-userdata-check: GET /latest/user-data/ [%d]%s",
           ar_http_status(resp),
           (ar_http_status(resp) == 200) ? " (user-data EXPOSED; verify)" : "");
    return 0;
}
