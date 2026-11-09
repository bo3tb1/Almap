/* http-vuln-cve2023-25690 - Apache mod_proxy request-smuggling probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[8192];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "POST", "/", NULL,
                        "Transfer-Encoding: chunked\r\n", "0\r\n\r\n",
                        "application/x-www-form-urlencoded",
                        resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 200 || code == 400 || code == 411)) {
        ar_out(ctx, "potentially vulnerable: CVE-2023-25690 Apache "
               "mod_proxy smuggling (HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: CVE-2023-25690 (HTTP %d)", code);
    }
    return 0;
}
