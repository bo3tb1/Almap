/* http-vuln-cve2024-27956-4 - WP Automatic SQL injection probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/wp-content/plugins/wp-automatic/inc/csv.php", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-27956-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "wp-automatic")) {
        ar_out(ctx, "VULNERABLE: /wp-content/plugins/wp-automatic/inc/csv.php [%d] (CVE-2024-27956)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-27956 (/wp-content/plugins/wp-automatic/inc/csv.php [%d])", ar_http_status(resp));
    }
    return 0;
}
