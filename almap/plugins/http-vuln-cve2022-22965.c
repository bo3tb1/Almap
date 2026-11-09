/* http-vuln-cve2022-22965 - Spring4Shell class-loader probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    const char *body;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/", NULL, "\r\n",
                        "class.module.classLoader.resources.context.parent."
                        "pipeline.first.pattern=ALMAP",
                        "application/x-www-form-urlencoded",
                        resp, sizeof(resp));
    if (n <= 0) {
        ar_out(ctx, "CVE-2022-22965: no response");
        return 0;
    }
    body = ar_http_body(resp);
    if (ar_contains_ci(body, "Whitelabel") ||
        ar_http_status(resp) == 400 || ar_http_status(resp) == 500) {
        ar_out(ctx, "potentially vulnerable: CVE-2022-22965 Spring4Shell "
               "(HTTP %d)", ar_http_status(resp));
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-22965 Spring4Shell "
               "(HTTP %d)", ar_http_status(resp));
    }
    return 0;
}
