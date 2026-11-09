/* http-vuln-cve2011-3192-2 - Apache Range header DoS probe. */
#include "arsenal_util.h"

int almap_script_run(AlScriptContext *ctx) {
    char resp[4096];
    int code;
    int n;

    if (!ar_valid(ctx)) {
        return 1;
    }
    n = ar_http_request(ctx, "GET", "/", NULL,
                        "Range: bytes=0-1,0-1,0-1,0-1,0-1,0-1,0-1,0-1\r\n",
                        NULL, NULL, resp, sizeof(resp));
    code = ar_http_status(resp);
    if (n > 0 && (code == 206 || code == 200)) {
        ar_out(ctx, "potentially vulnerable: CVE-2011-3192 Apache "
               "Range DoS (HTTP %d)", code);
    } else {
        ar_out(ctx, "not vulnerable: CVE-2011-3192 (HTTP %d)", code);
    }
    return 0;
}
