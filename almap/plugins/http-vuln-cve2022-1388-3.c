/* http-vuln-cve2022-1388-3 - F5 iControl REST auth bypass probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/mgmt/shared/authn/login", NULL,
                        "\r\n", "{\"username\":\"admin\",\"password\":\"\"}",
                        "application/json", resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 200 || ar_contains_ci(resp, "token"))) {
        ar_out(ctx, "potentially vulnerable: CVE-2022-1388 F5 "
               "iControl REST (HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: CVE-2022-1388 (HTTP %d)", code);
    }
    return 0;
}
