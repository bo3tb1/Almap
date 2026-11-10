/* http-vuln-cve2022-22947-4 - Spring Cloud Gateway SpEL probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/actuator/gateway/routes", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2022-22947-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "Spring")) {
        ar_out(ctx, "VULNERABLE: /actuator/gateway/routes [%d] (CVE-2022-22947)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-22947 (/actuator/gateway/routes [%d])", ar_http_status(resp));
    }
    return 0;
}
