/* http-vuln-cve2022-22965-3 - Spring4Shell class-loader probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/", NULL, "\r\n",
                        "class.module.classLoader.resources.context.parent."
                        "pipeline.first.pattern=ALMAP",
                        "application/x-www-form-urlencoded",
                        resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 200 || code == 400 || code == 500)) {
        ar_out(ctx, "potentially vulnerable: CVE-2022-22965 "
               "Spring4Shell (HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-22965 (HTTP %d)", code);
    }
    return 0;
}
