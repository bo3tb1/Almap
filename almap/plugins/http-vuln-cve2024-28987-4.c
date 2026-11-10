/* http-vuln-cve2024-28987-4 - SolarWinds Web Help Desk SSRF probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/SolarWinds/InformationService/v3/Json/Query", NULL, NULL, NULL, NULL,
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "http-vuln-cve2024-28987-4: no HTTP response");
        return 0;
    }
    if (ar_contains_ci(resp, "SolarWinds")) {
        ar_out(ctx, "VULNERABLE: /SolarWinds/InformationService/v3/Json/Query [%d] (CVE-2024-28987)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2024-28987 (/SolarWinds/InformationService/v3/Json/Query [%d])", ar_http_status(resp));
    }
    return 0;
}
